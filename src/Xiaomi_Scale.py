#!/usr/bin/python
# -*- coding: utf-8 -*-
import asyncio
import binascii
from bleak import BleakScanner
from collections import namedtuple
from Cryptodome.Cipher import AES
from datetime import datetime
import functools
import json
import paho.mqtt.publish as publish
import struct
import subprocess
import sys
import logging
import os

import Xiaomi_Scale_Body_Metrics

DEFAULT_DEBUG_LEVEL = "INFO"
VERSION = "0.4.0"

# Xiaomi S400 (MJTZC01YM) BLE MiBeacon device type and Body Composition data object IDs
XIAOMI_S400_DEVICE_ID = 0x3BD5
XIAOMI_S400_BODY_COMPOSITION_OBJ_ID = 0x6E16



# User Config
class USER:
    def __init__(self, name, gt, lt, sex, height, dob):
        self.NAME, self.GT, self.LT, self.SEX, self.HEIGHT, self.DOB


def customUserDecoder(userDict):
    return namedtuple('USER', userDict.keys())(*userDict.values())

def MQTT_discovery():
    """Published MQTT Discovery information if enabled in options.json"""
    for MQTTUser in (USERS):
        message = '{"name": "' + MQTTUser.NAME + ' Weight",'
        message+= '"state_topic": "' + MQTT_PREFIX + '/' + MQTTUser.NAME + '/weight",'
        message+= '"value_template": "{{ value_json.weight }}",'
        message+= '"json_attributes_topic": "' + MQTT_PREFIX + '/' + MQTTUser.NAME + '/weight",'
        message+= '"icon": "mdi:scale-bathroom",'
        message+= '"state_class": "measurement"}'
        publish.single(
                        MQTT_DISCOVERY_PREFIX + '/sensor/' + MQTT_PREFIX + '/' + MQTTUser.NAME + '/config',
                        message,
                        retain=True,
                        hostname=MQTT_HOST,
                        port=MQTT_PORT,
                        auth={'username':MQTT_USERNAME, 'password':MQTT_PASSWORD},
                        tls=MQTT_TLS
                    )
    logging.info(f"MQTT Discovery Setup Completed...")

def check_weight(user, weight):
    return weight > user.GT and weight < user.LT

def GetAge(d1):
    d1 = datetime.strptime(d1, "%Y-%m-%d")
    d2 = datetime.strptime(datetime.today().strftime('%Y-%m-%d'),'%Y-%m-%d')
    return abs((d2 - d1).days)/365
    
def MQTT_publish(weight, unit, mitdatetime, hasImpedance, miimpedance, heartRate=None):
    """Publishes weight data for the selected user"""
    if unit == "lbs": calcweight = round(weight * 0.4536, 2)
    if unit == "jin": calcweight = round(weight * 0.5, 2)
    if unit == "kg": calcweight = weight
    matcheduser = None
    for user in USERS:
        if(check_weight(user,weight)):
            matcheduser = user
            break
    if matcheduser is None:
        return
    height = matcheduser.HEIGHT
    age = GetAge(matcheduser.DOB)
    sex = matcheduser.SEX.lower()
    name = matcheduser.NAME

    lib = Xiaomi_Scale_Body_Metrics.bodyMetrics(calcweight, height, age, sex, 0)
    message = '{'
    message += '"weight":' + "{:.2f}".format(weight)
    message += ',"weight_unit":"' + str(unit) + '"'
    message += ',"bmi":' + "{:.2f}".format(lib.getBMI())
    message += ',"basal_metabolism":' + "{:.2f}".format(lib.getBMR())
    message += ',"visceral_fat":' + "{:.2f}".format(lib.getVisceralFat())

    if hasImpedance:
        lib = Xiaomi_Scale_Body_Metrics.bodyMetrics(calcweight, height, age, sex, int(miimpedance))
        bodyscale = ['Obese', 'Overweight', 'Thick-set', 'Lack-exercise', 'Balanced', 'Balanced-muscular', 'Skinny', 'Balanced-skinny', 'Skinny-muscular']
        message += ',"lean_body_mass":' + "{:.2f}".format(lib.getLBMCoefficient())
        message += ',"body_fat":' + "{:.2f}".format(lib.getFatPercentage())
        message += ',"water":' + "{:.2f}".format(lib.getWaterPercentage())
        message += ',"bone_mass":' + "{:.2f}".format(lib.getBoneMass())
        message += ',"muscle_mass":' + "{:.2f}".format(lib.getMuscleMass())
        message += ',"protein":' + "{:.2f}".format(lib.getProteinPercentage())
        message += ',"body_type":"' + str(bodyscale[lib.getBodyType()]) + '"'
        message += ',"metabolic_age":' + "{:.0f}".format(lib.getMetabolicAge())
        message += ',"impedance":' + "{:.0f}".format(int(miimpedance))

    if heartRate:
        message += ',"heart_rate":' + "{:.0f}".format(heartRate)

    message += ',"timestamp":"' + mitdatetime + '"'
    message += '}'
    try:
        logging.info(f"Publishing data to topic {MQTT_PREFIX + '/' + name + '/weight'}: {message}")
        publish.single(
            MQTT_PREFIX + '/' + name + '/weight',
            message,
            retain=MQTT_RETAIN,
            hostname=MQTT_HOST,
            port=MQTT_PORT,
            auth={'username':MQTT_USERNAME, 'password':MQTT_PASSWORD},
            tls=MQTT_TLS
        )
        logging.info(f"Data Published ...")
    except Exception as error:
        logging.error(f"Could not publish to MQTT: {error}")
        raise

def parse_s400(mac_bytes, service_data, bindkey):
    """Decode a Xiaomi S400 (MJTZC01YM) MiBeacon advertisement.

    Unlike the older V1/V2 scales, the S400 broadcasts its measurements
    inside an encrypted Xiaomi MiBeacon frame (service UUID 0xFE95). The
    frame needs to be decrypted with AES-CCM using the scale's per-device
    bind key before the Body Composition data object (0x6E16) can be read.
    The bind key can be extracted from the user's Xiaomi account, e.g. with
    https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor

    Returns a dict with any of 'weight' (kg), 'impedance' (Ohm) and
    'heart_rate' (bpm) present in the broadcast, or None if the
    advertisement isn't a decodable S400 Body Composition packet.
    """
    if len(service_data) < 5:
        return None

    frctrl = service_data[0] | (service_data[1] << 8)
    device_id = service_data[2] | (service_data[3] << 8)
    if device_id != XIAOMI_S400_DEVICE_ID:
        return None

    has_mac = (frctrl >> 4) & 1
    has_capability = (frctrl >> 5) & 1
    has_object = (frctrl >> 6) & 1
    is_encrypted = (frctrl >> 3) & 1

    if not has_object:
        return None

    offset = 5
    if has_mac:
        offset += 6
    if has_capability:
        capability = service_data[offset]
        offset += 1
        if capability & 0x20:
            offset += 1

    if is_encrypted:
        if not bindkey:
            logging.warning(f"S400 scale detected but MISCALE_BINDKEY is not configured, cannot decrypt data...")
            return None
        # MiBeacon v4/v5 AES-CCM: nonce = reversed MAC + device_id + packet_id + 3-byte counter,
        # ciphertext is followed by a 3-byte counter and a 4-byte auth tag.
        nonce = mac_bytes[::-1] + service_data[2:5] + service_data[-7:-4]
        tag = service_data[-4:]
        ciphertext = service_data[offset:-7]
        cipher = AES.new(bytes.fromhex(bindkey), AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x11")
        try:
            payload = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as error:
            logging.debug(f"S400 decryption failed, check MISCALE_BINDKEY: {error}")
            return None
    else:
        payload = service_data[offset:]

    result = {}
    pos = 0
    while pos + 3 <= len(payload):
        obj_id = payload[pos] | (payload[pos + 1] << 8)
        obj_len = payload[pos + 2]
        obj_data = payload[pos + 3:pos + 3 + obj_len]
        if obj_id == XIAOMI_S400_BODY_COMPOSITION_OBJ_ID and obj_len == 9:
            _, packed, _ = struct.unpack("<BII", obj_data)
            mass_raw = packed & 0x7FF
            heart_rate_raw = (packed >> 11) & 0x7F
            impedance_raw = packed >> 18
            if mass_raw:
                result["weight"] = mass_raw / 10
            if 0 < heart_rate_raw < 127:
                result["heart_rate"] = heart_rate_raw + 50
            if impedance_raw:
                result["impedance"] = impedance_raw / 10
        pos += 3 + obj_len
    return result or None

os.system('clear')

# Configuraiton...
# Trying To Load Config From options.json (HA Add-On)
try:
    with open('/data/options.json') as json_file:
        data = json.load(json_file)["options"]
        try:
            DEBUG_LEVEL = data["DEBUG_LEVEL"]
            if DEBUG_LEVEL not in ('CRITICAL','ERROR','WARNING','INFO','DEBUG','NOTSET'):
                DEBUG_LEVEL = DEFAULT_DEBUG_LEVEL
                logging.basicConfig(format='%(asctime)s - (%(levelname)s) %(message)s', level=DEBUG_LEVEL, datefmt='%Y-%m-%d %H:%M:%S')
                logging.info(f"-------------------------------------")
                logging.info(f"Starting Xiaomi mi Scale v{VERSION}...")
                logging.info(f"Loading Config From Options.json...")
                logging.warning(f"Invalid logging level provided, defaulting to {DEBUG_LEVEL}...")
            else:
                logging.basicConfig(format='%(asctime)s - (%(levelname)s) %(message)s', level=DEBUG_LEVEL, datefmt='%Y-%m-%d %H:%M:%S')
                logging.info(f"-------------------------------------")
                logging.info(f"Starting Xiaomi mi Scale v{VERSION}...")
                logging.info(f"Loading Config From Options.json...")
                logging.info(f"Logging Level Set to {DEBUG_LEVEL}...")
            # Prevent bleak log flooding
            bleak_logger = logging.getLogger("bleak")
            bleak_logger.setLevel(logging.INFO)
        except:
            DEBUG_LEVEL = DEFAULT_DEBUG_LEVEL
            logging.basicConfig(format='%(asctime)s - (%(levelname)s) %(message)s', level=DEBUG_LEVEL, datefmt='%Y-%m-%d %H:%M:%S')
            logging.info(f"-------------------------------------")
            logging.info(f"Starting Xiaomi mi Scale v{VERSION}...")
            logging.info(f"Loading Config From Options.json...")
            logging.info(f"No Logging Level Provided, Defaulting to  {DEBUG_LEVEL}...")
            # Prevent bleak log flooding
            bleak_logger = logging.getLogger("bleak")
            bleak_logger.setLevel(logging.INFO)
            pass
        try:
            MISCALE_MAC = data["MISCALE_MAC"]
            logging.debug(f"MISCALE_MAC read from config: {MISCALE_MAC}")

        except:
            logging.error(f"MAC Address not provided...")
            raise
        try:
            MISCALE_VERSION = data["MISCALE_VERSION"]
            logging.info(f"MISCALE_VERSION option is deprecated and can safely be removed from config...")
        except:
            pass
        try:
            MISCALE_BINDKEY = data["MISCALE_BINDKEY"]
            logging.debug(f"MISCALE_BINDKEY read from config: ***")
        except:
            MISCALE_BINDKEY = None
            logging.debug(f"MISCALE_BINDKEY not provided, S400 scale support will be disabled...")
            pass
        try:
            MQTT_USERNAME = data["MQTT_USERNAME"]
            logging.debug(f"MQTT_USERNAME read from config: {MQTT_USERNAME}")
        except:
            MQTT_USERNAME = "username"
            logging.debug(f"MQTT_USERNAME defaulted to: {MQTT_USERNAME}")
            pass
        try:
            MQTT_PASSWORD = data["MQTT_PASSWORD"]
            logging.debug(f"MQTT_PASSWORD read from config: ***")
        except:
            MQTT_PASSWORD = None
            logging.debug(f"MQTT_PASSWORD defaulted to: {MQTT_PASSWORD}")
            pass
        try:
            MQTT_HOST = data["MQTT_HOST"]
            logging.debug(f"MQTT_HOST read from config: {MQTT_HOST}")
        except:
            logging.error(f"MQTT Host not provided...")
            raise
        try:
            MQTT_RETAIN = data["MQTT_RETAIN"]
            logging.debug(f"MQTT_RETAIN read from config: {MQTT_RETAIN}")
        except:
            MQTT_RETAIN = True
            logging.debug(f"MQTT_RETAIN defaulted to: {MQTT_RETAIN}")
            pass
        try:
            MQTT_PORT = data["MQTT_PORT"]
            logging.debug(f"MQTT_PORT read from config: {MQTT_PORT}")
            if(type(MQTT_PORT) != int):
                logging.warning(f"Converting MQTT_PORT to integer...")
                MQTT_PORT = int(MQTT_PORT)
        except:
            MQTT_PORT = 1883
            logging.debug(f"MQTT_PORT defaulted to: {MQTT_PORT}")
            pass
        try:
            MQTT_TLS_CACERTS = data["MQTT_TLS_CACERTS"]
            logging.debug(f"MQTT_TLS_CACERTS read from config: {MQTT_TLS_CACERTS}")
        except:
            MQTT_TLS_CACERTS = None
            logging.debug(f"MQTT_TLS_CACERTS defaulted to: {MQTT_TLS_CACERTS}")
            pass
        try:
            MQTT_TLS_INSECURE = data["MQTT_TLS_INSECURE"]
            logging.debug(f"MQTT_TLS_INSECURE read from config: {MQTT_TLS_INSECURE}")
        except:
            MQTT_TLS_INSECURE = None
            logging.debug(f"MQTT_TLS_INSECURE defaulted to: {MQTT_TLS_INSECURE}")
            pass
        try:
            MQTT_PREFIX = data["MQTT_PREFIX"]
            logging.debug(f"MQTT_PREFIX read from config: {MQTT_PREFIX}")
        except:
            MQTT_PREFIX = "miscale"
            logging.debug(f"MQTT_PREFIX defaulted to: {MQTT_PREFIX}")
            pass
        try:
            TIME_INTERVAL = data["TIME_INTERVAL"]
            logging.info(f"TIME_INTERVAL option is deprecated and can safely be removed from config...")
        except:
            pass
        try:
            MQTT_DISCOVERY = data["MQTT_DISCOVERY"]
            logging.debug(f"MQTT_DISCOVERY read from config: {MQTT_DISCOVERY}")
        except:
            MQTT_DISCOVERY = True
            logging.debug(f"MQTT_DISCOVERY defaulted to: {MQTT_DISCOVERY}")
            pass
        try:
            MQTT_DISCOVERY_PREFIX = data["MQTT_DISCOVERY_PREFIX"]
            logging.debug(f"MQTT_DISCOVERY_PREFIX read from config: {MQTT_DISCOVERY_PREFIX}")
        except:
            if MQTT_DISCOVERY:
                logging.warning(f"MQTT Discovery enabled but no MQTT Prefix provided, defaulting to 'homeassistant'...")
                MQTT_DISCOVERY_PREFIX = "homeassistant"
            pass
        try:
            HCI_DEV = data["HCI_DEV"].lower()
            logging.debug(f"HCI_DEV read from config: {HCI_DEV}")
        except:
            HCI_DEV = "hci0"
            logging.debug(f"HCI_DEV defaulted to: {HCI_DEV}")
            pass
        try:
            BLUEPY_PASSIVE_SCAN = data["BLUEPY_PASSIVE_SCAN"]
            logging.debug(f"BLUEPY_PASSIVE_SCAN read from config: {BLUEPY_PASSIVE_SCAN}")
        except:
            BLUEPY_PASSIVE_SCAN = False
            logging.debug(f"BLUEPY_PASSIVE_SCAN defaulted to: {BLUEPY_PASSIVE_SCAN}")
            pass

        if MQTT_TLS_CACERTS in [None, '', 'Path to CA Cert File']:
            MQTT_TLS = None
        else:
            MQTT_TLS = {'ca_certs':MQTT_TLS_CACERTS, 'insecure':MQTT_TLS_INSECURE}

        USERS = []
        for user in data["USERS"]:    
            try:
                user = json.dumps(user)
                user = json.loads(user, object_hook=customUserDecoder)
                if user.GT > user.LT:
                    raise ValueError("GT can not be larger than LT - user {user.Name}")  
                USERS.append(user)
            except:
                logging.error(f"{sys.exc_info()[1]}")
                raise
        OLD_MEASURE = None
        logging.info(f"Config Loaded...")

# Failed to open options.json
except FileNotFoundError as error:
    DEBUG_LEVEL = DEFAULT_DEBUG_LEVEL
    logging.basicConfig(format='%(asctime)s - (%(levelname)s) %(message)s', level=DEBUG_LEVEL, datefmt='%Y-%m-%d %H:%M:%S')
    logging.info(f"-------------------------------------")
    logging.info(f"Starting Xiaomi mi Scale v{VERSION}...")
    logging.info(f"Loading Config From Options.json...")
    logging.error(f"options.json file missing... {error}")
    # Prevent bleak log flooding
    bleak_logger = logging.getLogger("bleak")
    bleak_logger.setLevel(logging.INFO)
    raise


async def main(MISCALE_MAC):
    stop_event = asyncio.Event()

    # TODO: add something that calls stop_event.set()

    def callback(device, advertising_data):
        global OLD_MEASURE
        if device.address.lower() == MISCALE_MAC:
            logging.debug(f"miscale found, with advertising_data: {advertising_data}")
            try:
                ### Xiaomi V2 Scale ###
                data = binascii.b2a_hex(advertising_data.service_data['0000181b-0000-1000-8000-00805f9b34fb']).decode('ascii')
                logging.debug(f"miscale v2 found (service data: 0000181b-0000-1000-8000-00805f9b34fb)")
                data = "1b18" + data # Remnant from previous code. Needs to be cleaned in the future
                data2 = bytes.fromhex(data[4:])
                ctrlByte1 = data2[1]
                isStabilized = ctrlByte1 & (1<<5)
                hasImpedance = ctrlByte1 & (1<<1)
                measunit = data[4:6]
                measured = int((data[28:30] + data[26:28]), 16) * 0.01
                unit = ''
                if measunit == "03": unit = 'lbs'
                if measunit == "02": unit = 'kg' ; measured = measured / 2
                miimpedance = str(int((data[24:26] + data[22:24]), 16))
                if unit and isStabilized:
                    if OLD_MEASURE != round(measured, 2) + int(miimpedance):
                        OLD_MEASURE = round(measured, 2) + int(miimpedance)
                        MQTT_publish(round(measured, 2), unit, str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S+00:00')), hasImpedance, miimpedance)
            except:
                pass
            try:
                ### Xiaomi V1 Scale ###
                data = binascii.b2a_hex(advertising_data.service_data['0000181d-0000-1000-8000-00805f9b34fb']).decode('ascii')
                logging.debug(f"miscale v1 found (service data: 0000181d-0000-1000-8000-00805f9b34fb)")
                data = "1d18" + data # Remnant from previous code. Needs to be cleaned in the future
                measunit = data[4:6]
                measured = int((data[8:10] + data[6:8]), 16) * 0.01
                unit = ''
                if measunit.startswith(('03', 'a3')): unit = 'lbs'
                if measunit.startswith(('12', 'b2')): unit = 'jin'
                if measunit.startswith(('22', 'a2')): unit = 'kg' ; measured = measured / 2
                if unit:
                    if OLD_MEASURE != round(measured, 2):
                        OLD_MEASURE = round(measured, 2)
                        MQTT_publish(round(measured, 2), unit, str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S+00:00')), "", "")
            except:
                pass
            try:
                ### Xiaomi S400 Scale ###
                sd = advertising_data.service_data['0000fe95-0000-1000-8000-00805f9b34fb']
                logging.debug(f"miscale s400 found (service data: 0000fe95-0000-1000-8000-00805f9b34fb)")
                mac_bytes = bytes.fromhex(device.address.replace(':', ''))
                s400 = parse_s400(mac_bytes, sd, MISCALE_BINDKEY)
                weight = s400.get("weight") if s400 else None
                if weight:
                    impedance = s400.get("impedance")
                    heart_rate = s400.get("heart_rate")
                    hasImpedance = impedance is not None
                    miimpedance = str(int(impedance)) if hasImpedance else ""
                    dedup_key = round(weight, 2) + (int(impedance) if hasImpedance else 0)
                    if OLD_MEASURE != dedup_key:
                        OLD_MEASURE = dedup_key
                        MQTT_publish(round(weight, 2), 'kg', str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S+00:00')), hasImpedance, miimpedance, heart_rate)
            except:
                pass
        pass

    async with BleakScanner(
        callback,
        device=f"{HCI_DEV}"
        ) as scanner:
        ...
        # Important! Wait for an event to trigger stop, otherwise scanner
        # will stop immediately.
        await stop_event.wait()

        
if __name__ == "__main__":
    if MQTT_DISCOVERY:
        MQTT_discovery()
    logging.info(f"-------------------------------------")
    logging.info(f"Initialization Completed, Waiting for Scale...")
    try:
        asyncio.run(main(MISCALE_MAC.lower()))
    except Exception as error:
        logging.error(f"Unable to connect to Bluetooth: {error}")
        pass
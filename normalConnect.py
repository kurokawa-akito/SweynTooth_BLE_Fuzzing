#!/usr/bin/python 
import os
import platform
import sys
import string
import random
from tinyec import registry
import secrets
from time import sleep

# libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
# timeout lib
from timeout_lib import start_timeout, disable_timeout, update_timeout

# Default master address
# master_address = 'E4:51:75:DA:99:B1'
# master_address = 'FF:FF:FF:FF:FF:FF'
master_address = '58:8E:81:70:26:FA'
access_address = 0x8e89bed6
# Internal vars
none_count = 0
end_connection = False
connecting = False
pairing_sent = False
feature_req_sent = False
switch_version_req_llid = False
miss_connections = 0
slave_addr_type = 1
# Autoreset colors
colorama.init(autoreset=True)

# Get serial port from command line
if len(sys.argv) >= 2:
    serial_port = sys.argv[1]
elif platform.system() == 'Linux':
    serial_port = '/dev/ttyACM0'
elif platform.system() == 'Windows':
    serial_port = 'COM24'
else:
    print(Fore.RED + 'Platform not identified')
    sys.exit(0)

print(Fore.YELLOW + 'Serial port: ' + serial_port)

# Get advertiser_address from command line (peripheral addr)
if len(sys.argv) >= 3:
    advertiser_address = sys.argv[2].lower()
else:
    # advertiser_address = '58:8E:81:70:26:FA'
    advertiser_address = '84:72:93:3C:5D:96'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())

driver = NRF52Dongle(serial_port, baudrate=115200)

# def crash_timeout():
#     print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
#           ' received\nThe device may have crashed!!!')

#################################################################
#Call API
#################################################################

def scan_timeout():
    global connecting, miss_connections, slave_addr_type
    scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    start_timeout('scan_timeout', 2, scan_timeout)
    if connecting:
        connecting = False
        miss_connections += 1
        if miss_connections >= 2:
            miss_connections = 0
            print(Fore.RED + 'Something wrong is happening\n'
                             'We are receiving advertisements but no connection is possible\n'
                             'Check if the connection parameters are allowed by peripheral\n'
                             'or optionally check if device works normally with a mobile app again.')

def random_number_generator_16bytes():
    random_number = ""
    for i in range(16):
        number = random.randint(0, 255)
        hex_number = hex(number)[2:].upper()
        random_number += "\\x" + hex_number.zfill(2)
    return random_number

def random_generate_32bytes_key():
    key = ""
    for i in range(32):
        num = random.randint(0, 255)
        hexNum = hex(num)[2:].upper()
        key += "\\x" + hexNum.zfill(2)
    return key

def compress(pubkey):
    return hex(pubkey.x) + hex(pubkey.y % 2)[2:]

curve = registry.get_curve('brainpoolP256r1')

def clearDriverBuffer(driver):
    driver.inputBufferClear()
    driver.outputBufferClear()
##################################################################

# Open serial port of NRF52 Dongle
# driver = NRF52Dongle(serial_port, baudrate=115200)
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

start_timeout('scan_timeout', 2, scan_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while True:
    pkt = None
    # Receive packet from the NRF52 Dongle
    length_data = False # addition
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue

        elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
            update_timeout('scan_timeout')
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "RX <--- " + pkt.summary()[7:])

        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower() and \
                connecting == False:
            connecting = True
            update_timeout('scan_timeout')
            disable_timeout('crash_timeout')
            slave_addr_type = pkt.TxAdd
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=78,  # 1.25ms windows offset (anchor connection point)
                interval=150,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=1000,  # Supervision timeout, 500ms (any)
                chM=0x1FFFFFFFFF,  # Any
                hop=7,  # Hop increment (any)
                SCA=0,  # Clock tolerance
            )

            driver.send(conn_request)
        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            feature_req_sent = False
            pairing_sent = False
            miss_connections = 0
            # start_timeout('crash_timeout', 5, crash_timeout)

            print(Fore.GREEN + 'Peripheral Connected (L2Cap channel established)')
            # Send version indication request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / BTLE_CTRL() / LL_VERSION_IND(version='5.0', subversion=0xd005)
            driver.send(pkt)  # send normal version request
        
        # additional
        elif ATT_Exchange_MTU_Request in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Response(mtu = 247)
            driver.send(pkt)
            clearDriverBuffer(driver)
        
        # Central-initiated Feature Exchange procedure
        elif LL_VERSION_IND in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_REQ(
                feature_set='le_encryption+le_data_len_ext')
            feature_req_sent = True
            driver.send(pkt)
            clearDriverBuffer(driver)

        # Peripheral-initiated Feature Exchange procedure
        elif LL_SLAVE_FEATURE_REQ in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_RSP(
                feature_set='le_encryption+le_data_len_ext+slave_init_feat_exch+ch_sel_alg')
            driver.send(pkt)

        # Central-initiated Data Length Exchange procedure
        elif LL_FEATURE_RSP in pkt:
            if feature_req_sent:
                feature_req_sent = False
                pkt = BTLE(access_addr=access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_REQ(
                    max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
                driver.send(pkt)
            else:
                print(Fore.RED + 'Ooops, peripheral replied with a LL_FEATURE_RSP without corresponding request\n'
                                 'This means that the peripheral state machine was just corrupted!!!')
                exit(0)

        # Peripheral-initiated Data Length Exchange procedure
        elif LL_LENGTH_REQ in pkt:
            length_rsp = BTLE(access_addr=access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_RSP(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(length_rsp)  # Send a normal length response
            clearDriverBuffer(driver)

            # send a pairing request
            if not pairing_sent:
                pairing_req = BTLE(
                    access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                    iocap=2, oob=0, authentication=0x0D, max_key_size=16, initiator_key_distribution=0x03,
                    responder_key_distribution=0x03)
                pairing_sent = True
                driver.send(pairing_req)
                clearDriverBuffer(driver)

        # fixed public key x and y
        elif SM_Pairing_Response in pkt:
            # alicePrivKey = secrets.randbelow(curve.field.n)
            # alicePubKey = alicePrivKey * curve.g
            # pubKeyX = compress(alicePubKey)
            # pubKeyX = pubKeyX[2:-1].upper()
            # formattedKeyX = "\\x" + "\\x".join(pubKeyX[i:i+2] for i in range(0, len(pubKeyX), 2))
            # encodeKeyX = formattedKeyX.encode()

            # bobPrivKey = secrets.randbelow(curve.field.n)
            # bobPubKey = bobPrivKey * curve.g
            # pubKeyY = compress(bobPubKey)
            # pubKeyY = pubKeyY[2:-1].upper()
            # formattedKeyY = "\\x" + "\\x".join(pubKeyY[i:i+2] for i in range(0, len(pubKeyY), 2))
            # encodeKeyY = formattedKeyY.encode()

            # pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Public_Key(
            #     key_x = encodeKeyX,
            #     key_y = encodeKeyY
            # )
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Public_Key(
                key_x = b'\x03\xBF\xC7\x77\x3A\xBD\x60\x72\x8E\x7A\xFF\x42\x55\x35\x04\xF7\x36\xE2\x52\x9D\x1E\xC5\x50\xAB\xDB\x85\x54\x5D\xFE\xF3\x1C\x11',
                key_y = b'\x05\xAF\xC9\x8A\xB0\xDF\xA0\x1D\x20\xA3\xC4\xE1\xD9\x12\xE7\x4A\xF5\x17\xD9\x7B\x19\x49\x29\x73\x5D\x42\x90\xAA\x77\xF7\xDF\x41')
            driver.send(pairing_req)
            clearDriverBuffer(driver)

        # send pairing confirm
        elif SM_Public_Key in pkt:
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Confirm(
                
            )
            driver.send(pairing_req)
        
        # send pairing random (0x00 is pass, but it should not be)
        elif SM_Confirm in pkt:
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Random(
                random = bytearray(random_number_generator_16bytes())
            )
            driver.send(pairing_req)

        # send dhkey_check (failed)
        elif SM_Random in pkt:
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_DHKey_Check(
                dhkey_check = b'\xd5\x5f\x1b\x21\x7a\x98\x42\x14\x64\x91\xc6\xcb\x6f\xcd\xce\x75')
            driver.send(pairing_req)

        elif ATT_Find_By_Type_Value_Request in pkt:
            pkt = BTLE(
                access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Find_By_Type_Value_Response()
            driver.send(pkt)

    sleep(0.01)

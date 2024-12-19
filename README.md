# SweynTooth_BLE_Fuzzing
## Introduction  
This project is a rewritten version based on the testing methods of [SweynTooth](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks).  
## Experiment Environment  
![image](https://github.com/user-attachments/assets/ab26eda6-c398-46a6-bc2d-0494e273e782)  
* Advertiser: EFR32xG22
* Scanner: nRF52840 Dongle
## BLE Fuzzing Procedure
1. The victim device will broadcast connectable advertising packets.
2. The nRF52840 dongle will send scan requests and subsequently establish a connection with the victim device.
3. Once connected, the nRF52840 dongle can transmit the fuzzed data.
## Experiment Result
* Using Python library “Scapy” can customize the packet’s PDU data.
* The picture shows the packets exchange detail between the nRF52840 dongle and victim device.
![image](https://github.com/user-attachments/assets/1ce4ef36-de9b-46aa-b778-e57a481e922f)


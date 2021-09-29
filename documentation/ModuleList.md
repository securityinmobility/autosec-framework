#  Modules for the Autosec-Framework

## Modules already implemented

## Modules in implementation

- OBD2-Data retrieval 
- UDS CAN Id resolver
- CAN MITM bridge
- Assisted Reverse-Engineering of CAN-Signals (currently out of scope HATS3)

## Modules to be implemented

- Intercept, sniff and participate in Car-2-X-Communication (DSRC, ETSI ITS G5 / 802.11p) with modified WLAN hardware or SDRs
- Scan and attack automotive infotainment interfaces (WLAN, Bluetooth, USB, SD Card slots)
- Identify, scan and attack automotive debugging interfaces (e.g. (automotive) ethernet interfaces, hidden infotainment interfaces through USB-Ethernet-Interfaces)
- Analyze, sniff and modify the communication between charging stations and electric vehicles 
  - Different protocols used, e.g. simple PWM for AC charging, powerline communication (PLC) at DC charging
  - Prerequisite: PLC development board for H007 DC charging station is implemented and functional
- Create attacks for RF interfaces (Key fobs, TPMS, NFC features like smartphone key)
  - One way to implement attacks on Key-Fobs is shown in [here](https://labs.jumpsec.com/car-hacking-manual-bypass-of-modern-rolling-code-implementations/), the author also confirmed, that other OEMs can be attacked [Twitter](https://twitter.com/iamscarecrow1/status/1420649272169664513?s=21)
- Analyze the cellular network traffic of a vehicle
  - This could be done either by an analysis of the wireless connection, but this seems challenging for modern LTE networks
  - alternatively the in-vehicle network could be monitored as modern architectures use a dedicated access point for the internet access
  - this method is risky, because if the vehicle uses TLS connections, this way wouldn't bring much benefit
- Further analysis of the OEM diagnostic features (in case the ISO-TP channels are known)
- Implement attacks on the EOL function of airbags (deployment of all pyrotechnic actuators before the vehicle is scraped)
- Implement attacks on the CAN Network
  - Various attacks possible:
    - Bus flood
    - Frame spoofing (with or without causing a Arbitration Doom Loop)
    - Adaptive frame spoofing
    - Error passive spoofing (not through a CAN transceiver)
    - Double receiving attack (through manipulated EOF0 field)
    - Bus-Off Attack (Force a ECU off the bus due to repeated errors)
    - Freeze Doom Loop Attacks (using a legacy feature of CAN)
  - Analyse and attack CAN security mechanisms (IDS, Hardware, Gateways, Encryption)
  - Attacks are described e.g. in [here](https://canislabs.com/wp-content/uploads/2020/05/1901-2019-11-29-White-Paper-CAN-Security.pdf)


## Other implementation work

- Create and implement a concept to control and visualize automotive penetration tests

# Other subjects (possibly for a thesis)

-  Automotive usage of TEEs (Trusted Execution Environments)
-  Testing of neuronal networks used in automotive domain (e.g., Tesla Autopilote)

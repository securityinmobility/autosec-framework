# Modules for the Autosec-Framework

# Possible Thesis topics (german)

- Aufbau eines Zwischensteckers zum mitschneiden der Kommunikation an DC Ladesäulen
- Aufbau einer DC-Ladesäule mit Sniffing Funktionalität
- Aufbau eines Car2X WLANp/802.11p Sniffing Prüfstandes mit Consumer Hardware
- Konzeption zum mitschneiden von Cellular-V2X Kommunikation
- Analyse der Angriffsfläche von Infotainment Systemen über die Bluetooth Schnittstelle
- Analyse der Angriffsfläche von Infotainment Systemen über die USB Schnittstelle
- Analyse der Angriffsfläche von Infotainment Systemen über die WLAN Schnittstelle
- Analyse der Angriffsfläche von Infotainment Systemen über die Rundfunk Schnittstelle [1](https://arstechnica.com/cars/2022/02/radio-station-snafu-in-seattle-bricks-some-mazda-infotainment-systems/)
- Analyse von Logdateien aus Automotive Steuergeräten zur forensischen Verwertung
- Fuzzing von Bluetooth Implementierung (A2DP, PBAP, SDAP)

## Other possible theses topics (not related to autosec-framework / HATS3)

- Identifizieren von Javascript Bibliotheken in gebündelten Dateien
- Firmware und Protokollanalyse eines elektrischen Kleinstkraftfahrzeug (E-Scooter)
- Firmware und Protokollanalyse von Sharing Kleinstkraftfahrzeug (E-Scootern)
- Analyse der Backend Services von Sharing Anbietern
- Vergleichende Analyse verschiedener Intermediate Representation (IR) Modelle auf Ihre Eignung für platform-unabhängige statische Analysen

## Work in progress modules and theses

- OBD2-Data retrieval
- Implementierung von CAN Angriffen mithilfe von FPGAs (flooding, frame spoofing, adaptive frame spoofing)
- Assisted Reverse-Engineering of CAN-Signals
- User interface concept to control and visualize automotive penetration tests

## Finished modules and theses

- "Konzeptionierung einer DC Fast Charging Ladesäule mit Zugriff auf die Power Line Communication"
- UDS CAN ID finder
- CAN MITM bridge

## Module Idea Brainstorming

- Intercept, sniff and participate in Car-2-X-Communication (DSRC, ETSI ITS G5 / 802.11p) with modified WLAN hardware or SDRs
- Scan and attack automotive infotainment interfaces (WLAN, Bluetooth, USB, SD Card slots)
  - possible attacks on BT shown in this [article](https://www.bleepingcomputer.com/news/security/bluetooth-braktooth-bugs-could-affect-billions-of-devices/)
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

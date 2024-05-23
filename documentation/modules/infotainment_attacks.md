# Infotainment Attacks Module

## Submodule Overview

| Interfaces                | Submodule                      | Description                     | Required Hardware     |
|---------------------------|--------------------------------|---------------------------------|-----------------------|
| **Bluetooth and WiFi**    | **WirelessFormatstringAttack** | FSA via bluetooth and wifi name | ESP32 Devkit C V4     |
| **USB**                   | **KeystrokeInjectionAttack**   | Try keystroke injection as HID  | Arduino Zero          |
| **WiFi, Ethernet or USB** | **NetworkScanner**             | Device scan of the network      | (USB2Ethernet dongle) |
| **WiFi, Ethernet or USB** | **PortScanner**                | Port scan of a device           | (USB2Ethernet dongle) |

## WirelessFormatStringAttack Submodule

> Interactive attack

### Preparations

- Connect ESP32 to framework
- Be ready to check for nearby bluetooth devices and/or nearby wifi networks in the infotainment system

### Input Resources

- The COM port of the ESP32 connection (COMPort)

### Procedure

- The attack will load one payload after another as bluetooth and wifi name
- The user will be asked what is displayed in the infotainment system for each payload

### Output Resources

- The results of all the payloads (WirelessFormatstringResult)

## KeystrokeInjectionAttack Submodule

> Interactive attack

### Preparations

- Connect the Arduino Zero (connection order is important)
    1. Connect Native Port to target car
    2. Connect Programming Port to framework
- Connect to an internet interface of the target car
- Be ready to check for infotainment system behaviour

### Input Resources

- The COM port of the Arduino Zero connection (COMPort)
- The connected internet interface (InternetInterface)

### Procedure

- The attack will load one payload after another and inject keystrokes over the arduino
- The user will be asked questions about infotainment system behaviour

### Output Resources

- The results of all the payloads (KeystrokeInjectionResult)

## NetworkScanner Submodule

> Automated attack

### Preparations

- Connect to an internet interface of the target car

### Input Resources

- The connected internet interface (InternetInterface)

### Procedure

- The attack will use ARP, ICMP and passive network sniffing to detect network devices
- All possible ipv4 addresses in the given network are checked

### Output Resources

- The found devices (InternetDevice)

## PortScanner Submodule

> Automated attack

### Preparations

- Connect to an internet interface of the target car

### Input Resources

- The device to scan (InternetDevice including the connected InternetInterface)
- The range of tcp ports to scan (PortRange)

### Procedure

- The attack will use SYN-Scanning to detect open ports on the target device
- All ports in the given range are checked

### Output Resources

- The found services (InternetService)

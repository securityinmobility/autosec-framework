# EV Charging Station Discovery Module

## Overview

This project contains a Python script designed to discover Electric Vehicle (EV) charging stations on a local network using UDP broadcast over IPv6. The discovery process is encapsulated in the `EVChargingStationFinder` class, which is part of the `autosec` framework. The `test.py` script demonstrates how to use this module to find and list EV charging stations on the specified network interface.

## test.py

```python

'''
Required modules 
'''
from autosec.core.ressources.ip import InternetInterface
from autosec.modules.ev_charging_station_discovery import EVChargingStationFinder

'''
The following is required to specify the interface, The ipv4 address and the subnet length are not required. 
'''
inet_iface = InternetInterface("eth0", ipv4_address="0.0.0.0", subnet_length=20)

'''
The main function that should need to run
'''
results = EVChargingStationFinder().run([inet_iface])

'''
The following are the results that should be shown as outcomes from the ev_charging_station_discovery.py script 
'''
for result in results:
    secc_ip = result.get_device().get_ipv6()
    tcp_port = result.get_port()
    print(f"IP Address of the Charging Station: {secc_ip}")
    print(f"\nTCP Port number of the Charging Station: {tcp_port}\n")

```

## Prerequisites

Before running the script, ensure you have the required modules installed and correctly configured. The script depends on the `autosec` framework, specifically the `InternetInterface` class and the `EVChargingStationFinder` module.

## Project Structure

- **ev_charging_station_discovery.py**: Contains the core logic for discovering EV charging stations.
- **test.py**: A test script that demonstrates how to use the discovery module to find and display EV charging stations.

## How It Works

### 1. Setup the Network Interface

The `test.py` script starts by defining the network interface that will be used to broadcast the UDP packet:

```python
inet_iface = InternetInterface("eth0", ipv4_address="0.0.0.0", subnet_length=20)
```

- **Interface Name**: `"eth0"` is specified as the network interface to be used. You can change this to another interface (e.g., `"wlan0"` for Wi-Fi).
- **IPv4 Address & Subnet Length**: The IPv4 address and subnet length are not necessary for the discovery process and can be set to defaults.

### 2. Discovering EV Charging Stations

The main functionality of the script is to use the `EVChargingStationFinder` module:

```python
results = EVChargingStationFinder().run([inet_iface])
```

- **Module Initialization**: The `EVChargingStationFinder` is initialized and executed. The `run` method triggers the discovery process on the provided network interface.
- **UDP Broadcast**: The script sends a specially crafted UDP broadcast packet to the local network, targeting all devices in the `ff02::1` multicast group (all IPv6 nodes on the local link).
- **Response Handling**: The module listens for responses from EV charging stations and parses the data to extract relevant information (such as the station's IPv6 address and TCP port).

### 3. Displaying Results

After running the discovery module, the script iterates over the discovered services and prints out the results:

```python
for result in results:
    secc_ip = result.get_device().get_ipv6()
    tcp_port = result.get_port()
    print(f"IP Address of the Charging Station: {secc_ip}")
    print(f"\nTCP Port number of the Charging Station: {tcp_port}\n")
```

- **Output**: For each discovered EV charging station, the script outputs the IPv6 address and TCP port, which are crucial for establishing further communication with the station.

### Example Output

When you run the script, you might see an output like this (depending on the network setup and availability of EV charging stations):

```
IP Address of the Charging Station: fe80::abcd:1234:5678:9abc
TCP Port number of the Charging Station: 45868
```

## Running the Script

To run the `test.py` script, follow these steps:

1. **Ensure dependencies are installed**: Ensure that the `autosec` framework and all necessary modules are installed in your environment.
   
2. **Modify the network interface**: If needed, change the network interface name in `test.py` to match your environment (e.g., replace `"eth0"` with your actual interface name).

3. **Execute the script**: Run the `test.py` script:

   ```bash
   python test.py
   ```

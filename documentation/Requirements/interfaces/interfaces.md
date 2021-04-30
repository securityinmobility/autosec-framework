# Interfaces to be integrated within the framework

Within this document the interfaces / adapters that shall be integrated within the framework to communicate with the device under test (DUT) are collected and described. Furthermore, concrete requirements regarding their integration shall be formulated.

## Possible communcation channels with the DUT

Based on the document 08_Dokumentation/Bewertungsmatrix_ST.xlsx

### CAN

- Used in most vehicles as it is an easy and cheap way of connecting multiple ECUs
- physical layer consists of two twisted wires, bus is terminated with 120 Ohm on both sides
- multi-master bus, priority is handled by the lower message ID winning (as "0" is dominant bit, the ID with the more heading zero bits is winning)
  - No time-slots or a deterministic transfer possible
  - Message can alway be overwritten or manipulated (by writing the dominant bit)
- Different connections to a PC possible, within the order list a "Peak PCAN" USB CAN transceiver is planned
  - this transceive has a "opened" interface an can therefore be accessed with standard-tools
  - most tools are able to use these interfaces
  - especially under linux there is an almost standard calles SocketCAN that provides an interface to the transceiver with the same communcation strategies as used with TCP/UDP sockets
- The CAN bus is also used to provide diagnostic access to the vehicle via the OBD-II port (using UDS)
  
### LIN

- very slow master-slave bus that needs only one wire (+ GND)
- used for small components with only few functions (e.g. window buttons, buttons on the steering wheel)
- master asks the different components to transmit their data, each component then puts their data on the bus
- there are some failure detection mechanisms (checksum, pairity bits) that could cause an error within the master's stack
- As there are mainly small components with no or very little logic accessible via LIN, this is not a main attack vector
- The CAN transceiver (Peak PCAN) is able to communicate via LIN, therefore at least the monitoring of LIN busses should be implemented (maybe additionally interfering with some messages)

### Flexray

- not used within all vehicles
- mainly vehicles with bigger and more complex architectures use Flaxray mainly for safety- and therefore timing relevant ECUs
- Each cyclic frame has a fixed and a variable part
  - in the fixed part each message / ECU has a slot to transmit timing-relevant data
  - according to this data there may be additional data stored in the variable part but it's not deterministic if this data can be transmitted within the next cycle as the variable part is shared between all clients of the bus
- as there are fixed slots it is not trivial to inject messages
  - this would require a MITM access and very strict timing requirements (could be done by using a FPGA as shown by different researchers)
- The (complete) access to a flexray is not very common for an attacker
  - If he has access to the flexray (and possibly other busses) he could simply destroy the bus or stop any communcation by the insallation of a short circuit
  - Therefore a injection or manipulation of the Flexray has no top priority for the framework
  - Installation of a monitoring access would be suitable for a first implementation (FPGAs are planne on the order list)

### (Automotive) Ethernet / BroadR-reach

- more and more common in vehicles, manily within complex architectures or if there are fast connections needed (e.g. between the instruments cluster and a head unit)
- as the transceivers are getting cheaper, more and more busses will use this technology as there are several benefits
  - easy use of standard technology (e.g. TCP/IP stack, ViWi, RESTful-APIs) and their benefits (e.g. security mechanisms)
  - testing is mainly possible with standard hardware
  - high data rates possible
  - easy adjustable (compared to flexray or lin with their fixed slots)
- For the connection of ECUs within the vehicle mainly BroadR-reach is used as Layer 1/2 (communication with single twisted pair cable) with up to 100Mbit/s full duplex
  - not directly compatible with standard ethernet (e.g. 100BASE-TX needs a twisted pair cable per direction)
  - media converters are available, but not yet planned
- At least the access via the OBD-II port is available via "standard" ethernet (specification regarding pinning and activation line within ISO-13400)
  - This connection is used for DoIP (Diagnostics over IP), a way to use the diagnostic capabilities (e.g. updating, troubleshooting) faster than with CAN
  - the payload is still UDS (unified diagnostic services), but it is transfered via TCP/IP (TCP and (for detection) UDP Port 13400 at the vehicle side)
  - next to the port 13400 for DoIP it is possible that the vehicle may offer other open ports that can be used as a attack vector
- Communication with the OBD-II port via ethernet shall be implemented, this network interface can be used with standard-tools

### Bluetooth

- most moder vehicles offer a bluetooth interface to connect a mobile device to use the vehicle's infotainment system as hands-free device
- some other features may be availyble as well (e.g. Android Auto / Apple Car-Play) that may use the bluetooth connection as well
- if this interface is not secured properly, a attack may be possible
  - as the connection may be possible outside of the vehicle this could be very attractive to attackers
- Another possible attack vector could be a bluetooth low energy interface that is explicitly used outside of the vehicle
  - Can be a cheaper alternative to RFID to be able to use a smartphone as key to open the vehicle
  - If the vehicle is providing such a function, it is a potential attack vector (e.g. VAG China)

### WLAN (802.11a/g/n)

- some modern vehicles have a wifi hotspot to connect mobile devices to use the vehicle's cellular connection or even to stream music to the car's infotainment system
- As this signal may also be available outside of the vehicle, this is a access point for attacks that doesn't need physical access
- The connection to the vehicle is based on standard and widely spread technology (TCP/IP) and therfore is testable with standard tools
- For the connection of the vehicle's hotspot to the testing equipment one of the three wifi cards shall be used

### WLAN (802.11.p / Car-to-X, VANET / WAVE)

- next to the wifi of the infotainment system modern vehicles are beginning to integrate an external Car-to-X-communication interface
- one of those standards (mainly spread in europe) is Dedicated Short Range Communication that is used for toll collection systems
- another standard is WAVE
- all modern (not cellular) standards are based on a physicall and access layer called 802.11p, based on 802.11a but in a 5,9 GHz band and some adjustments [1]
- To be able to build the physcal and access layer the planed wifi cards may be used
  - they have to be adjusted to work in the specified band, possible way described [here](https://ctu-iig.github.io/802.11p-linux/) (additionally the driver has to be enabled to perform in OCB mode)
  - Protocol implementation of the ETSI C-ITS could be used from Raphael Riebl (THI) [here](https://github.com/riebl/vanetza)

### Plug-And-Charge (ISO 15118)

- Plug and Charge following the IS 15118 describes the communication between a PHEV or BEV and the carging station
- Additionally to charging parameters like the needed voltage and amperage it is possible to transfer additional data, like billing information
  - By providing the billing information over this interface, the customer doesn't need to authorize the charging process by handling a RFID card or other mechanisms
  - The user simply plugs in the vehicle, vehicle and charging station communicate and then the charging process starts, therefore the name "plug-and-charge"
- As there is a communication channel to the vehicle that transmits sensitive data (e.g. billing information) this is a possible attack vector
- To be able to analyse this communication, a PnC-communication shall be enabled in the laboratory
  - on the order list a development board for this communication is planned
  - a controllable power supply is already available and may be used to enable a real "supervised" charging station

### Cellular Network (2/3/4G, 5G)

- At least to provide the mandatory emergency call, all vehicles have a connection to a cellular network
- for additional online services, most modern vehicles have additional 3 or 4G connections, upcoming vehicles also 5G
- As the vehicles are therefore part of the Internet of Things, this interfaces has to be secured
- To test the used security measures, a LTE and 2G base station shall be ordered

### Other technologies

#### MOST

- MOST is an (in some variants) optical bus based on a ring-architecture
- mainly used within the infotainment-system e.g. between a main-unit and a dvd reader
- In case the ring is opened no communication is possible
- Depending on the architecture of the bus and the connected ECUs there may be a injetion of messages or eavesdropping could make sense, but due to the infotainment domain this has no big attack surface

#### LVDS 

- LVDS is mainly used to transfer video data within the vehicle (e.g. from a sensor to the ECU)
- it is not a bus as it is only used for point-to-point-connections, but there may be usecases when e.g. camera data shall be injected
- No inteface that shall be implemented within the first stage

#### RFID

- Most prominent usage of RFID in the automotive industry is the immobilizer, that needs a key generated in the vehicle's key, to be deactivated
- Vehicles communicate with the key using a RFID chip in the key
- Additionally, PKES (Passive Keyless Entry and Start)/ RES (Remote Keyless Entry) systems may be used and can be an additional attack vector
  - PKES is often prone to relay attacks
  - Predecessor of RES are RF systems (usually pressing a key to lock / unlock) with no / rolling code (based on counter) or other authentication
  - Often vehicles have weak cryptography and additionally only some master keys for lot of vehicles (e.g. VW Group)[2]
- SDR with range of 433/315/868 MHz and RFID (125kHz) for immobilizer would be needed
- SDR could be implemented by using low-cost RTL-DVBT-Sticks
- Not planed in the first implementation

# Sources

[1] DOI 10.1007/s00502-015-0343-0
[2] Lock It and Still Lose It – On the (In)Security of Automotive Remote Keyless Entry Systems
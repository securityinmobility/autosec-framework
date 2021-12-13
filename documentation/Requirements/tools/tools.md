# Tools to be integrated within the Security Framework

As there are many standard tools for many tasks of the security testing process available, theses tools shall be integrated within the securtiy testing framework. A list of possibly helpful tools, that may be integrated, shall be developed here. Therefore, the purpose, licence, API etc. of the tools shall be collected.

The integration of each of these tools may be a concrete, detailed system requirement. These requirements are linked to HATS3-Req-9. Additionally, there may be some requirements describing the technical interface between the integration modules and the framework itself.

## Tools recommended by [0]

### nmap
- Tool for network discovery and security auditing
- OpenSource (GNU GPL)
- Command Line Tool
- integratable using [libnmap](https://libnmap.readthedocs.io/en/latest/)

### OpenVAS
- "Open Vulnerability Assessment Scanner"
- followed / forked Nessus to stay under GPL
- complete vulnerability scanning tool that uses a daily updated community feed
- Client-Server Model (server is maintained and controlled by a web interface)
- After an activation, a proprietary API (vie the GMP - Greenbone Management Protocol) is available
- XML based interface, can be used with the command-line or python-shell gvm-tools (have to be installed additionally)
- Scanner to find vulnerabilites

### Metasploit
- One of the biggest / most used tools for vulnerability scanning and exploitation
- Framework is under BSD licence, there is also a commercial variant available (Metaspolit Pro)
- Controlled via a java GUI or command line (Ruby-based, Command line interface is also available via API)
- Especially the Hardware-Bridge-API seems to be interesting in the automotive sector as it enables attacks on IoT / Automotive Systems
  - There is even a lib / some tools for automotive testing https://oxhat.blogspot.com/2019/04/exploring-metasploit-hardware-bridge.html
  - Some tools for UDS are included as well, e.g. TesterPresent
  - The used way of connecting additional interfaces (that are not supported directly, like SocketCAN) could be used to deisgn the generiv adapter interface

### Aircrack-NG
- Tools for scanning and exploiting Wifi vulnerabilites (maybe also usable for 802.11p? -> If it's working on OSI-2 it should be possible)
- Works with the Atheros AR9285 in the THI Pentesting Lab (Ursula)

### Other
- W3af (as Web-Application framework not suitable)
- John the Ripper (PW-cracker, as there should not be any passwords within the applications itself maybe not relevant)
- Setoolkot not relevant because SocialEngineering is out of scope

## Tools recommended / mentioned by [1]
- Core topic is the performance (latency, Tx-/Rx-Rate) of different CAN Interfaces (Hardware, Adapter, Drivers) under Linux and Windows or embedded devices
  - Linux is in some criterias not as good as windows, the Vector HW is better regarding latency than the PEAK hardware (embedded boards of course better)
  - PCAN on windows (python-can) as good as SocketCAN regarding the Latency
- List of protocols for automotive security testing is provided:
  - CAN (ISO 11898)
  - Unified Diagnostic Services (UDS) (ISO 14229)
  - General Motor Local Area Network (GMLAN)
  - CAN Calibration Protocol (CCP)
  - Universal Measurement and Calibration Protocol (XCP) 
  - ISO-TP (ISO 15765)
  - Diagnostic over Internet Protocol (IP) (DoIP) (ISO 13400) 
  - On-board diagnostics (OBD) (ISO 15031) 
  - Ethernet (ISO 8802/3)
  - TCP/IP (RFC 793, RFC 7323 / RFC 791, RFC 2460)

### Busmaster
- Open Source Tool to simulate, analyze and test bus systems (CAN / LIN)
- Is able to run scripts like CAPL (Vector / CANoe), at least a conversion from CAPL into a busmaster format is provided

### c0f
- https://github.com/zombieCraig/c0f
- "CAN of Fingers"
- passive tool for fingerprinting CAN traces (adaption of p0f)

### can-utils
- Part of SocketCAN / Linux pre-installed can drivers
- Brings some usefull tools to communicate, dump and sniff

### CANiBUS
- Application to build a server that provides multiple clients a simultaneous access to one or multiple CAN devices

### CANtoolz
- https://github.com/CANToolz/CANToolz
- aka YACHT (Yet Another Car Hacking Tool)
- Can be used for multiple actions on CAN networks
  - ECU discovery, MitM testing, fuzzing, brute-forcing, scanning or R&D, testing and validation
- Framework of different other tools to ease the installation and the use
- Limited HW Support

### Caring Caribou
- https://github.com/CaringCaribou/caringcaribou
- Easy to use tool to analyze CAN networks for services and vulnerabilities
- python module that can be extended
- comes with functionalities for fuzzing, uds, xcp, dumping, listening, test suite running etc.
- new modules can be integrated easily

### Kayak
- https://dschanoeh.github.io/Kayak/
- Java tool for easy access to CAN data via SocketCAN
- Can view messages rawly as well as interpreted as messages

### CANSPY
- Can be used for CAN MITM / real time attacks with COTS Hardware
- CANYSPY presentation itself mentions Scapy

### Metasploit
- see mention in listing of tools from [0]

### O2OO
- Car diagnostic tool (OBD2 compliant) to log / print / visualize diagnostic data

### pyfuzz_can
- Probalby a python fuzzing tool for CAN networks
- Open Source (code is at least available on Github)

### python-OBD
- OBD2 implementation for python that supports a sepcific USB-OBD2 plug

### Scapy
- python tool to send, sniff, dissect and forge network packages
- Very common tool for network analysis

### UDSIM
- Graphical simulator to emulate modules in vehicles that respond to UDS requests
- Is able to learn the behaviour from live vehicle network traffic (e.g. while the vehicle is analysed by an UDS client and UDSim is monitoring this traffic)
- Integrated fuzzer to attack the uds server

## Other tools

### Venetza
- https://github.com/riebl/vanetza
- implemented by Raphael Riebl
- Implementation of the ETSI C-ITS protocol and other, car-to-X communication relevant protocols
- may be used to communication with the vehicle via the car-to-X interface and to test the security measures of this attack vector

### SavvyCAN
- https://github.com/collin80/SavvyCAN
- Qt based CAN tool
- visualization / reverse-engineering / debugging of CAN messages
- can load&save various CAN dump formats

# Links

- Installation of Metasploit (and OpenVAS) under Ubuntu 20.04 [here](https://hedgehogsecurity.co.uk/blog/2020/10/06/installing-metasploit/)

# Sources

[0] [Penetration Testing for Internet of Things and Its Automation - Ge Chu, Alexei Lisitsa](https://doi.org/10.1109/HPCC/SmartCity/DSS.2018.00244)
[1] [A Survey on Media Access Solutions for CAN Penetration Testing - Enrico Pozzobon, Nils Weiss, Sebastian Renner](https://doi.org/10.1145/3273946.3273949), DOI seems broken, thus [direct link](https://www.researchgate.net/publication/328687253_A_Survey_on_Media_Access_Solutions_for_CAN_Penetration_Testing)

# HATS3: Interface API Requirements

In order to fulfill the high-level requirements HATS3-Req-3 (different architectures), HATS3-Req-6 (Charging station communication), HATS3-Req-7 (partial systems) and HATS3-Req-9 (standard tools) the different interfaces of the device under test shall communicate through a defined API with the framework. This enables a generic way to communicate with the different interfaces of the vehicle offering a open system that is easy to expand.

Of course the differnet interfaces and especially the different bus technologies have different communication behaviour and therefore don't offer the same capabilities for external communication. But the API shall standardize the most common ways to communicate without cutting the individual capabilites.

To be able to use standard tools with this API the way of integrating hardware interfaces of some tools have to be evaluated. The most common tool is the Metasploit Framework (MSF) that has a special Hardware API. This is the first blueprint of how the HATS3 Interface API shall look like.

## Needed or useful functionality of the communication

To be able to use the interfaces for penetration testing some functionalities have to be available. These consist of:

- watch / monitor and record the traffic on this chanel / bus
- insert / inject messaged to the bus (incl. replay of recorded traces)
- suppress specific messages
- modify specific messages
- flood the bus
- change communication behaviour (e.g. bus modes)
- emulate an ECU (or parts of its capabilities)

The different functionalities may not be able on every bus. Therefore, the following table shall give an overview on which bus may support which function. The selected technologies are the most common 

||CAN|LIN|Flexray|Ethernet|Bluetooth|WLAN|WLAN-p|PnC|Cellular|
|---|---|---|---|---|---|---|---|---|---|
|monitor|yes|yes|yes|partly|partly|partly|yes|yes|unknown|
|insert|yes|yes|partly|partly|partly|partly|yes|yes|unknown|
|supress|yes|yes|unknown|unknown|partly|partly|yes|yes|unknown|
|modify|partly|partly|partly|unknown|unknown|unknown|unknown|yes|unknown|
|flood|yes|yes|partly|yes|yes|yes|yes|yes|yes|
|behaviour|no|partly|partly|no|unknown|no|no|yes|no|

Emulation is possible within all technologies that allow writing to the bus.

In some technologies the possible influence on the communication is depending on the security measures. E.g. ethernet can be monitored without any problems, but the link may use protocols like TLS that encrypt the data. Therefore it can't be said what is possible in general.

## Common standard tools & interfaces

### SocketCAN

SocketCAN is the state-of-the-art interface for the communication with open CAN devices under linux. It enables a socket-based communication comparable to network interfaces. This interface can also be accessed direclty from the Metasploit Framework by usage of the hardware bridge api.
For the usage of socketCAN the package can-utils brings some very handy functionalities, that can be used. These are described in the following section:

|Tool|Description|Usage|
|---|---|---|
|candump|Monitor CAN bus traffic|monitor, flood|
|canbusload|Monitor CAN bus load|monitoring, flood|
|cangen|CAN data generator|flood|
|cangw|Gateway functionality for can interfaces|supress, modify|
|canplayer|Replay CAN frame logfile|insert, flood, replay|
|cansniffer|Monitor bus with changes of IDs|monitor|
|canlogserver|Log CAN messages|montor|
|cansend|Send CAN message|insert, modify, flood|

There are mutliple other tools inclueded within the can-utils described [here](https://github.com/linux-can/can-utils/blob/master/README.md).

Additionally, the isotp tools can be used as well. isotp is a transport prototol that can be used if a bigger payload than CAN's 8 byte is needed (e.g. diagnsotic responses with UDS).

### Socket Access

For the communication with network interfaces the linx socket api can be used. By using this api, raw data can be sent. Additionally, if needed, other socket implementations like UDP/TCP for DoIP communication can be used in a similar way.

## Metasploit HW-Bridge API

Basically the server (auxiliary/server/local_hwbridge) offers a RESTful interface at which the relay services can connect to. One implementation is auxiliary/client/hwbridge/connect for CAN -> these services could be written for other interfaces as well.

Unfortunately, the documentation site as it is references within multiple articles (opengarages.ord/hwbridge) is not available.

The HW-Bridge consists of two pieces: A HTTP Server with a REST interface that is attached to the physical device (e.g. a CAN transceiver) ans a connector module (client) that interacts with other metasploit modules. The client gets the URI of the server interface and uses different services to trigger actions like sending data on the transceiver.
Therefore, a interface that is  not yet supported by the MSF can be enabled by writing a HTTP server that provides the necessary interfaces.
As of now, the client itself only provides and uses methods to interact with CAN transceivers and so do the available automotive exploits.

The server is acting as a relay service that enables the communication between the MSF and the non-ethernet/wifi device. If the device itself is able to create a webserver that supports the REST interface, the support can be implemented in the device itself and no relay service is necessary.

### Relay server ressources and implementation

The relay service can be built within the MSF, but this is not necessary. A standard HTTP server that can handle several GET requests should be sufficient.

The following ressources are provided by the exemplary CAN server provided in the MSF (modules/auxiliary/server/)


uri =~ /status$/i
    print_status("Sending status...") if datastore['VERBOSE']
    send_response_html(cli, get_status().to_json(), { 'Content-Type' => 'application/json' })

-> Send current status with the following data:
status = {}
    status["operational"] = @operational_status # 0=unk, 1=connected, 2=not connected

    status["hw_specialty"] = {}
    status["hw_capabilities"] = {}
    status["last_10_errors"] = @last_errors # NOTE: no support for this yet
    -> These three are empty as of now
    status["api_version"] = HWBRIDGE_API_VERSION
    status["fw_version"] = "not supported"
    status["hw_version"] = "not supported"
    unless @can_interfaces.empty?
      status["hw_specialty"]["automotive"] = true
      status["hw_capabilities"]["can"] = true
    end
    status["hw_capabilities"]["custom_methods"] = true # To test custom methods
    custom methods are speciial methods a hardware bridge may offer to use functions depending on the interface or the protocoll used
    status

uri =~ /statistics$/i
    print_status("Sending statistics...") if datastore['VERBOSE']
    send_response_html(cli, get_statistics().to_json(), { 'Content-Type' => 'application/json' })

    stats["uptime"] = Time.now - @server_started
    stats["packet_stats"] = @packets_sent
    stats["last_request"] = @last_sent if @last_sent
    stats["voltage"] = "not supported"

request.uri =~ /settings\/datetime\/get$/i
    print_status("Sending Datetime") if datastore['VERBOSE']
    send_response_html(cli, get_datetime().to_json(), { 'Content-Type' => 'application/json' })

request.uri =~ /settings\/timezone\/get$/i
    print_status("Sending Timezone") if datastore['VERBOSE']
    send_response_html(cli, get_timezone().to_json(), { 'Content-Type' => 'application/json' })

request.uri =~ /custom_methods$/i
    print_status("Sending custom methods") if datastore['VERBOSE']
    send_response_html(cli, get_custom_methods().to_json(), { 'Content-Type' => 'application/json' })

    m = {}
    m["Methods"] = []
    meth = { "method_name" => "custom/sample_cmd", "method_desc" => "Sample HW test command", "args" => [] }
    arg = { "arg_name" => "data", "arg_type" => "string", "required" => true }
    meth["args"] << arg
    meth["return"] = "string"
    m["Methods"] << meth
    m
- Custom methods and their usage in the framework have to be investigated further

request.uri =~ /custom\/sample_cmd\?data=(\S+)$/
    print_status("Request for custom command with args #{$1}") if datastore['VERBOSE']
    send_response_html(cli, sample_custom_method($1).to_json(), { 'Content-Type' => 'application/json' })

request.uri =~ /automotive/i
- Automotive is a kind of "integrated custom method"
    if request.uri =~ /automotive\/supported_buses/
    print_status("Sending known buses...") if datastore['VERBOSE']
    send_response_html(cli, get_auto_supported_buses().to_json, { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /automotive\/(\w+)\/cansend\?id=(\w+)&data=(\w+)/
    print_status("Request to send CAN packets for #{$1} => #{$2}##{$3}") if datastore['VERBOSE']
    send_response_html(cli, cansend($1, $2, $3).to_json(), { 'Content-Type' => 'application/json' })
    elsif request.uri =~ /automotive\/(\w+)\/isotpsend_and_wait\?srcid=(\w+)&dstid=(\w+)&data=(\w+)/
    bus = $1; srcid = $2; dstid = $3; data = $4
    print_status("Request to send ISO-TP packet and wait for response  #{srcid}##{data} => #{dstid}") if datastore['VERBOSE']
    opt = {}
    opt['TIMEOUT'] = $1 if request.uri =~ /&timeout=(\d+)/
    opt['MAXPKTS'] = $1 if request.uri =~ /&maxpkts=(\d+)/
    opt['PADDING'] = $1 if request.uri =~ /&padding=(\d+)/
    opt['FC'] = true if request.uri =~ /&fc=true/i
    send_response_html(cli, isotp_send_and_wait(bus, srcid, dstid, data, opt).to_json(),  { 'Content-Type' => 'application/json' })
    
    else
    send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
    end
else
    send_response_html(cli, not_supported().to_json(), { 'Content-Type' => 'application/json' })
end
- automotive, zigbee and rftransceiver are built into the MSF, additionally, custom methods can be provided by the hardware interface


#### Automotive custom functions

/automotive\/(\w+)\/cansend\?id=(\w+)&data=(\w+)/

(w+ = word)

-> Send a CAN frame on the device / bus (first word) with the ID (second word) and the data (3rd word)


/automotive\/(\w+)\/isotpsend_and_wait\?srcid=(\w+)&dstid=(\w+)&data=(\w+)/

-> Send a ISO-TP Frame with ID and Data on specific bus and wait for answer with another ID (with certain optional parameters)

As of now, there is no method for general monitoring or logging of the CAN channels provided. Supressing or modification of messages isn't possible either.
For usual UDS communication (request/response) the implemented "isotpsend_and_wait" method is sufficient. The used lib-functions are provided within metasploit-framework/lib/msf/core/post/hardware/automotive/uds.rb

Another module (elm327_relay.rb) creates a interface to the can bus by using a serial interface.

#### zigbee custom functions

The zigbee / killerbee server (metasploit-framework/tools/hardware/killerbee_msfrelay.py ) contains functions to inject, sniff and read data. To do so, the Killerbee framework is used.

### Benefit of integration of metasploit

As Metasploit is one of the biggest and one of the most pupular penetration testing tools and there are many modules, payloads and exploits within the framework, an integration would bring some benefits. As there are currently ony a few dedicated automotive modules (e.g. UDS service discovery, some specific modules for specific vehicles and a CAN-flood module), the benefit on this side is very limited.

As other interfaces of the vehicle, like the interfaces of the infotainment system (WLAN, Bluetooth etc.) are also considered as attack vector, in these steps the metasploit framework could bring bigger benefits, especially as these systems may be built on other, popular platforms (Linux, Windows SE, Android etc.) or may have dedicated interfaces to popular systems (Apple CarPlay, AndroidAuto) that could have special exploits in metasploit. The needed interfaces are already integrated in the framework (WLAN, Ethernet etc.), so there are no special requirements that have to be fulfilled by the framework.

Due to the fact that most exploits and attacks are specialized on a specific interface, a generic interface for all devices may not be that benefit. A mechanism to log all outgoing and incoming data may be easily implemented and would be a bigger benefit. Therefore, the integration of different tools under a common interface shall be preferred.


## Mirage

"Mirage: towards a Metasploit-like framework for IoT"; Cayre et al.

Within the Mirage framework a framework for the security testing of IoT devices with different wireless technologies that is comparable to metasploit was built. The main benefit is the integration of different wireless communication technologies that can be accessed through a single API. 

To archieve this, the basic operation of sending and revceiving data through an interface is implemented within the framework itself. Additional to the basic hardware-specific access a kind of translator between raw bytes and the interface's target data representation has to be built for a new interface to be integrated. For these two modules it is possible to publish specific methods (e.g. if the interface is capable to manipulate certain messages) and to offer their use to other modules.

The basic sending or receiving is provided though Emitter / Receiver modules that access the underlying devices. These devices are managed in a registry pattern and therefore they're only instantiated once even if they're used multiple times. This corresponds with the physical availability of the hardware ressources.

These modules are extended by generic util- and io-modules that can be used for tasks different technologies need. 

The core part of the framework organizes the different modules and also provides callbacks for certain events. Other modules are built on top of that and provide modular steps of the penetration testing process, like information gathering, sniffing, injections, modifications, scans... These small and modular elements can be chained together within the framework using either more complex scenarios or by the usage of a piping mechanism that is built in.

Frameworks for specific usecases are built-in in mirage (e.g. Killerbee for testing of zigbee devices), but no general pen-testing framework or tools (e.g. msf) are part of mirage.


## Generic signature of the different actions

In the following part the signatures of the methods used by the different interfaces with their specific capabilites shall be listed.

### CAN

Within the CAN protocol and by using the PCAN devices it is possible to send and receive certain CAN messages. These messages have an identifier and can carry up to 8 bytes. To send longer messages usually ISO-TP is used.

To send a message on a can bus, the bus, the identifier and the bytes to be sent have to be known.

bool: sendMessageOnCan(bus, id, data[])

Depending on the length of the data it could automatically be switched between standard CAN and ISO-TP. 
There's no direct or linked answer mechanism that could return any data. Therefore, a simple state should be returned indicating that the message was sent successfully.

Receiving messages on CAN is simple in case of single-frame messages (8 or less bytes). In case of more data, all frames have to be collected and re-arranged to get the message itself. This is mainly used within diagnositc data and is limited up to 4kB. Both messages have an identifier, that has to be known.
Additionally, it is possible to "listen" to multiple messages. It is possible to wait for one message with that identifiert and then go on or to continously receive certain messaged. The later would imply to use a kind of callback or a pipe to store the data.

-> Mirage Framework, the different capabilities are listed -> such a list has to be done for the used interfaces as well.

## Conclusion for the AutoSec Framework

The different actions on the hardware (with different targets as information gathering, exploitation, scanning, attacks and so on) are often dedicated for specific busses. The different technologies are all able to transfer use data, but the art of the interaction between the tools and the hardware including the bus technology differ a lot. Attacks on Ethernet via TCP can not be compared to CAN attacks with single broadcas messages or even with a request/response protocol as UDS is.

With this in mind, there is no big benefit in the creation of a common hardware interfaces that can handle requests to all the different interfaces. More relevant is a generic way to use different tools and mechanisms within the penetration testint process.
This generic interface could work like the modular metasploit framework by a consol applocation that offers different modules to perform dedicatet actions. To be able to adopt this framework for automotive security, different tools, especially for automotive systems as descibed in the tools document, shall be contained. The information of the interface the specific action needs as well as its purpose (attack, exploit, scanner, sniffer etc.), a textual description and the needed parameters have to be listed.

With such a framework a generic usage of high-level modules is possible and can potentially be used for a knowledge database as well as for a recommendation system or even automatization. 

Additionally, a low level interface to sniff the performed communication is of interest. Therefore, afterwards a specific investigation of what has been done and what consequences these actions had is possible. Additionally, if an automatization on a lower (communication) level is of interested, the data might be usefull. This can be implemented by a proxy interface, that splits the communication streams between the actual (hardware) interface and a listener, that could write all the data to a file (e.g. PCAP) and/or show the communication in real-time.
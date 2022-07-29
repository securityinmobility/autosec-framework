Test manual:

Note: It is enough to set up the vcans once.

can_mitm_test.py:
    -   set up two vcans on Linux terminal:
        sudo modprobe vcan
        sudo ip link add name vcan0 type vcan
        sudo ip link add name vcan1 type vcan
        sudo ip link set dev vcan0 up
        sudo ip link set dev vcan1 up
    -   use cangen from can-utils to generate random data:
        cangen vcan0 
        cangen vcan1
    -   now execute the can_mitm_test

can_sniff_test.py: 
    -   set up one vcan on Linux terminal:
        sudo modprobe vcan
        sudo ip link add name vcan0 type vcan
        sudo ip link set dev vcan0 up
    -   execute the can_sniff_test

isotp_test.py: 
    -   set up one vcan on Linux terminal:
        sudo modprobe vcan
        sudo ip link add name vcan0 type vcan
        sudo ip link set dev vcan0 up
    -   start the isotp_test (test may take a while)

ip_test.py: 
    -   start ip_tests with the sudo command


automatic_execution_test.py:
    -   set up one vcan on Linux terminal:
        sudo modprobe vcan
        sudo ip link add name vcan0 type vcan
        sudo ip link set dev vcan0 up
    -   start automatic_execution_test.py in sudo mode

replay_trc_test.py:
    -   set up one vcan on Linux terminal:
        sudo modprobe vcan
        sudo ip link add name vcan0 type vcan
        sudo ip link set dev vcan0 up
    -   start replay_trc_test  (uses headlight-right-idle.trc file)
    -   start scapy in the terminal with command: scapy
        -   Initialize: conf.contribs['CANSocket'] = {'use-python-can': False}
                        load_contrib('cansocket')
        -   Initialize socket: socket = CANSocket(channel="vcan0")
        -   Sniff send packets: packets = socket.sniff(timeout=2)
        -   Show data:
             for p in packets: 
                print(p.identifier, " ", p.data)
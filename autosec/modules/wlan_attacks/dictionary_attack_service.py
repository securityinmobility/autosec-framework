from typing import List, Union
import os
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.wifi import WifiInformation, FourWayHandshake, WlanPSW
from .dictionary_attack import DictionaryAttack


def load_module() -> List[AutosecModule]:
    return [DictionaryAttackService()]


class DictionaryAttackService(AutosecModule):

    def __init__(self) -> None:
        super().__init__()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to crack the wifi password from a captured 4-way-handshake",
            dependencies=["scapy"],
            tags=["WIFI", "dictionary attack", "wordlist", "WPA", "WPA2"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [
            WlanPSW(wlan_psw="secret psw")
        ]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [
            WifiInformation(
                ssid="hack_me",
                bssid_mac="ff:ff:ff:ff:ff:ff",
                channel=1,
                pwr=-80,
                beacon_count=1,
                enc="WPA2/PSK",
                group_cipher_suite="[CCMP-128]",
                pairwise_cipher_suites="[CCMP-128]",
                akm_suites="[PSK]"
            ),
            FourWayHandshake(handshake=Union[None])
        ]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        wifi_information: WifiInformation = self.get_ressource(
            inputs=inputs,
            kind=WifiInformation
        )
        handshake: FourWayHandshake = self.get_ressource(
            inputs=inputs,
            kind=FourWayHandshake
        )
        dictionary_attack: DictionaryAttack = DictionaryAttack(
            ssid=wifi_information.get_ssid(),
            handshake=handshake.get_handshake(),
            dictionary_folder=f"{os.getcwd()}/autosec/modules/wlan_attacks/dictionary/my_wordlists"
        )
        return [
            WlanPSW(
                wlan_psw=dictionary_attack.get_wlan_psw()
            )
        ]

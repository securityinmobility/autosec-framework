from typing import List
import os
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.wifi import WifiInformation
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
        return []

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [
            WifiInformation(
                ssid="hack_me",
                bssid_mac="ff:ff:ff:ff:ff:ff",
                channel=1
            )
        ]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        wifi_information: WifiInformation = self.get_ressource(
            inputs=inputs,
            kind=WifiInformation
        )
        DictionaryAttack(
            ssid=wifi_information.get_ssid(),
            dictionary_folder=f"{os.getcwd()}/autosec/modules/wlan_attacks/dictionary/my_wordlists"
        )
        return []

from typing import List
import time
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.base import NetworkInterface
from autosec.core.ressources.wifi import WifiInformation
from .information_gathering import InformationGathering


def load_module() -> List[AutosecModule]:
    return [InformationGatheringService()]


class InformationGatheringService(AutosecModule):

    def __init__(self) -> None:
        super().__init__()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to collect information about existing wifi networks",
            dependencies=["scapy", "pandas"],
            tags=["WIFI", "information gathering"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
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
            )
        ]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [
            NetworkInterface(interface="wlo1")
        ]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        network_interface: NetworkInterface = self.get_ressource(
            inputs=inputs,
            kind=NetworkInterface
        )
        info: InformationGathering = InformationGathering(
            iface=network_interface.get_interface_name(),
            hopping_channel=True
        )
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            pass
        info.stop()
        time.sleep(5)
        wifi_ap_information: List[WifiInformation] = []
        for _, ap_info in info.get_access_points_information().items():
            wifi_ap_information.append(
                WifiInformation(
                    ssid=ap_info["|SSID|"],
                    bssid_mac=ap_info["|BSSID|"],
                    channel=ap_info["|Channel|"],
                    pwr=ap_info["|PWR|"],
                    beacon_count=ap_info["|#Beacons|"],
                    enc=ap_info["|ENC|"],
                    group_cipher_suite=ap_info["|Group Cipher Suite|"],
                    pairwise_cipher_suites=ap_info["|Pairwise Cipher Suites|"],
                    akm_suites=ap_info["|AKM Suites|"]
                )
            )
        return wifi_ap_information

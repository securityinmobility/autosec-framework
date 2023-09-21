from typing import List, Union
import time
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.base import NetworkInterface
from autosec.core.ressources.wifi import WifiInformation, FourWayHandshake
from .deauthentication import Deauthentication
from .capture_handshake import CaptureHandshake


def load_module() -> List[AutosecModule]:
    return [HandshakeDeauthService()]


class HandshakeDeauthService(AutosecModule):

    def __init__(self) -> None:
        super().__init__()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to capture the 4-way-handshake between client and AP of an existing wifi. Deauthentication of clients from wifi network is necessary",
            dependencies=["scapy"],
            tags=["WIFI", "4-way-handshake", "capture", "WPA", "WPA2", "EAPOL", "deauthentication"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [FourWayHandshake]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [NetworkInterface, WifiInformation]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        network_interface: NetworkInterface = self.get_ressource(
            inputs=inputs,
            kind=NetworkInterface
        )
        wifi_information: WifiInformation = self.get_ressource(
            inputs=inputs,
            kind=WifiInformation
        )
        deauth: Deauthentication = Deauthentication(
            iface=network_interface.get_interface_name(),
            channel=wifi_information.get_channel(),
            bssid_mac=wifi_information.get_bssid_mac(),
            count=0,
            delay=3.0
        )
        handshake = CaptureHandshake(
            iface=network_interface.get_interface_name(),
            channel=wifi_information.get_channel()
        )
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            pass
        deauth.stop()
        time.sleep(5)
        return [
            FourWayHandshake(
                handshake=handshake.stop()
            )
        ]

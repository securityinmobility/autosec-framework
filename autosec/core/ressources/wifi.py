from scapy.layers.dot11 import PacketList
from .base import AutosecRessource


class WifiInformation(AutosecRessource):

    def __init__(self, ssid: str, bssid_mac: str, channel: int) -> None:
        self._ssid: str = ssid
        self._bssid_mac: str = bssid_mac
        self._channel: int = channel

    def get_ssid(self) -> str:
        return self._ssid

    def get_bssid_mac(self) -> str:
        return self._bssid_mac

    def get_channel(self) -> int:
        return self._channel


class FourWayHandshake(AutosecRessource):

    def __init__(self, handshake: PacketList) -> None:
        self._handshake: PacketList = handshake

    def get_handshake(self) -> PacketList:
        return self._handshake


class WlanPSW(AutosecRessource):

    def __init__(self, wlan_psw: str) -> None:
        self._wlan_psw: str = wlan_psw

    def get_wlan_psw(self) -> str:
        return self._wlan_psw

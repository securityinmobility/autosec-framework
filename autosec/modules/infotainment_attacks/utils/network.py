"""
Utils for network actions
"""
from os.path import dirname, join
from typing import IO

from autosec.core.ressources import InternetDevice

__author__: str = "Michael Weichenrieder"


class ManufacturerMatcher:
    """
    Tool for mapping manufacturers to mac addresses
    """

    _manufacturer_mapping_file: str = join(dirname(__file__), "manufacturer_mapping.txt")

    @classmethod
    def update_manufacturers(cls, internet_devices: [InternetDevice]) -> [InternetDevice]:
        """
        Fill in the manufacturers for internet devices

        :param internet_devices: List of internet devices to fill in manufacturers
        :return: The input list (no copy) with filled in manufacturers
        """
        # Prepare structures to store devices and their manufacturers
        macs_left: {InternetDevice, str} = {}
        for internet_device in internet_devices:
            try:
                macs_left[internet_device] = cls._mac_to_binary(internet_device.get_mac())
            except Exception:
                # Ignore devices without mac
                pass
        manufacturers: {InternetDevice, str} = {}

        # Read file line by line
        file: IO = open(cls._manufacturer_mapping_file, mode="r", encoding="utf-8")
        for line in file.read().splitlines():
            # Exit if all macs were found
            if len(macs_left) == 0:
                break

            # Skip empty or comment lines
            if line == "" or line.startswith("#"):
                continue

            # Get prefix
            prefix: str = line[:line.index("\t")]
            binary_mac: str
            if "/" in prefix:
                # Non-half mac prefix
                mac: str = prefix[:prefix.index("/")]
                bits: int = int(prefix[prefix.index("/") + 1:])
                binary_mac = cls._mac_to_binary(mac, bits)
            else:
                # Half mac prefix
                binary_mac = cls._mac_to_binary(prefix)

            # Compare and save (don't remove, because it might need to be overwritten later)
            for internet_device, binary_mac_left in macs_left.items():
                if binary_mac_left.startswith(binary_mac):
                    manu: [str] = line.split("\t")[1:3]
                    if len(manu) == 1:
                        manufacturers[internet_device] = manu[0]
                    elif len(manu) > 1:
                        manufacturers[internet_device] = (manu[1])

        # Fill in manufacturer info for internet devices
        for internet_device in internet_devices:
            if internet_device in manufacturers:
                internet_device.set_manufacturer(manufacturers[internet_device])

        # Return results
        return internet_devices

    @classmethod
    def _mac_to_binary(cls, mac: str, bits: int = -1) -> str:
        """
        Converts a mac to binary and returns the first n bits if set

        :param mac: The mac to convert to binary
        :param bits: The number of bits to return (or -1/unset to return all)
        :return: The binary mac address
        """
        # Convert mac to binary
        binary_mac: str = mac.replace(":", "")
        binary_mac = bin(int(binary_mac, 16))[2:].rjust(len(binary_mac) * 4, "0")

        # Crop if requested
        if bits != -1:
            binary_mac = binary_mac[:bits]

        # Return binary mac
        return binary_mac

"""
This module starts the vanetza application and the dependencies 
Dependencies:
mqtt server (currently using mosquitto)
"""
import os
import signal
import subprocess
from typing import List
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.modules.wlan_p.ocb_join import OcbModeJoin


def load_module() -> List[AutosecModule]:
    """
    Load module
    """
    return NotImplementedError

class Vanetza(AutosecModule):
    """
    This module starts the NAP vanetza application.
    Everytime the wifi interface is joined a new network this app need to be restarted
    """
    def __init__(self, executable: str = '/usr/local/bin/socktap', config_file: str = '') -> None:
        super().__init__()
        self._executable = executable
        self._config_file = config_file

    # Default installation directory from vanetza tool socktap
    _executable: str = '/usr/local/bin/socktap'
    _config_file: str = ''
    _pid: int = 0

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to start the socktap application of vanetza",
            dependencies=["scapy", "pandas"],
            tags=["C2X", "vanetza", "socktap"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        Requirement is a configured WiFi interface
        """
        return [OcbModeJoin, MQTTserver]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

    def start_vanetza(self):
        """
        Starts the socktap application from the nap-vanetza project
        """
        self._executable: str = '/home/user/jaf0789/nap-vanetza/vanetza_src/bin/socktap'
        self._config_file: str = '/home/user/jaf0789/nap-vanetza/vanetza_src/tools/socktap/config.ini'
        process = subprocess.Popen([
            self._executable, \
            '-c', \
            self._config_file
        ],
        # capture_output=False,
        # check=False,
        )
        self._pid = process.pid

    def stop_vanetza(self):
        """
        Stops the socktap application
        """
        os.kill(self._pid, signal.SIGTERM)

class MQTTserver(AutosecModule):
    """
    This module handels the startup of the mosquitto MQTT server
    """
    _type: str = 'listener'
    _port: int = 1883
    _bind_address: str = '0.0.0.0'
    _allow_anonymous: bool = True

    _executable: str = '/usr/sbin/mosquitto'
    _config_file: str = ''
    _pid: int = 0

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to start a mosquitto server",
            dependencies=["scapy", "pandas"],
            tags=["C2X", "MQTT", "mosquitto"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        Output is the mqtt server
        """
        return [MQTTserver]

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        No requirements, only starts local mqtt server
        """
        return []

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

    def write_config(self):
        """
        Writes the configuration for the mqtt server.
        """
        curr_dir = os.path.dirname(__file__)
        self._config_file = os.path.join(curr_dir, 'mosquitto.conf')
        with open(self._config_file, "w", encoding='UTF-8') as file_handle:
            file_handle.writelines(self._type + ' ' + \
                            str(self._port) + ' ' + \
                            self._bind_address + '\n')
            file_handle.writelines('allow_anonymous ' + \
                            str(self._allow_anonymous).lower() )
    def delete_config(self):
        """
        Deletes the configuration for the mqtt server
        """
        os.remove(self._config_file)

    def start_mosquitto(self):
        """
        Starts the mosquitto server in the background
        Attention: _executable can be misused for arbitrary code execution
        """
        self.write_config()
        process = subprocess.Popen(
            [self._executable, \
                "-c", 
                self._config_file, \
                # "-d", \
                ],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._pid = process.pid

    def stop_mosquitto(self):
        """
        Stops the mosquitto server
        """
        os.kill(self._pid, signal.SIGTERM)
        self.delete_config()

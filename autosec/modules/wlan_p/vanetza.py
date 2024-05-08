"""
This module starts the vanetza application and the dependencies 
Dependencies:
mqtt server (currently using mosquitto)
"""
import configparser
import os
import signal
import subprocess
from typing import List, Tuple
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.wlan_p import MqttInstance, OcbInterface, VanetzaInstance
from autosec.modules.wlan_p.ocb_join import OcbModeJoin


def load_module() -> List[AutosecModule]:
    """
    Load module
    """
    return [Vanetza()]

class Vanetza(AutosecModule):
    """
    This module starts the NAP vanetza application.
    Everytime the wifi interface is joined a new network this app need to be restarted
    """
    # Default installation directory from vanetza tool socktap
    _executable: str = '/usr/local/bin/socktap'
    _config_file: str = ''
    _pid: int = 0

    def __init__(self, executable: str = '/usr/local/bin/socktap', config_file: str = '') -> None:
        super().__init__()
        self._executable = executable
        self._config_file = config_file

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to start the socktap application of vanetza",
            dependencies=["scapy", "pandas"],
            tags=["C2X", "vanetza", "socktap"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        Output is a started vanetza instance in the background
        """
        return [VanetzaInstance]

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        Requirement is a configured WiFi interface
        """
        return [OcbInterface, MqttInstance]

    def run(self, inputs: Tuple[OcbInterface, MqttInstance]) -> List[AutosecRessource]:
        """
        Starts the Vanetza application
        """
        interface, mqtt = inputs
        self.write_config(interface._interface_name, mqtt.ip, mqtt.port)
        self.start_vanetza()
        ret_vanetza = VanetzaInstance
        ret_vanetza._launched = True
        ret_vanetza._pid = self._pid
        return [VanetzaInstance]

    def start_vanetza(self):
        """
        Starts the socktap application from the nap-vanetza project
        """
        process = subprocess.Popen([
            self._executable, \
            '-c', \
            self._config_file
        ],
        # capture_output=False,
        # check=False,
        )
        self._pid = process.pid 

    def write_config(self, wifi_interface: str, mqtt_broker_ip: str, mqtt_port: str):
        """   
        Writes the configuration for vanetza.
        """
        config = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes=[';'])
        
        with open(self._config_file, "r", encoding='UTF-8') as file_handle:
            config.read_file(file_handle)

        config.set('general', 'interface', wifi_interface)
        config.set('general', 'local_mqtt_broker', mqtt_broker_ip)
        config.set('general', 'local_mqtt_port', str(mqtt_port))
        config.set('cam', 'periodicity', '0')
        
        with open(self._config_file, "w", encoding='UTF-8') as file_handle:
            config.write(file_handle)


    def stop_vanetza(self):
        """
        Stops the socktap application
        """
        os.kill(self._pid, signal.SIGTERM)

class MqttBroker(AutosecModule):
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

    def __init__(self, ip: str = '0.0.0.0', port: int = 1883) -> None:
        super().__init__()
        self._port = port
        self._bind_address = ip

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
        return [MqttInstance]

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        No requirements, only starts local mqtt server
        """
        return []

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        """
        Start the MQTT Broker
        """
        self.start_mosquitto()
        
        # Create Ressource to return
        ret_mqtt = MqttInstance
        ret_mqtt.ip = self._bind_address
        ret_mqtt.port = self._port
        ret_mqtt._launched = True

        return [ret_mqtt]

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

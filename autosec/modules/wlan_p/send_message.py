"""
Module for sending an ITS-G5 message. Supports:
DENM (Decentralized Environmental Notification Messages)
CAM (Cooperative Awareness Messages)
"""
from functools import reduce
import operator
import os
from typing import List, Tuple
import json
#import jsonschema
import paho.mqtt.client as mqtt
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.wlan_p import MqttInstance, OcbInterface


def load_module() -> List[AutosecModule]:
    """
    Load module
    """
    return [SendMessage()]

class SendMessage(AutosecModule):
    """
    This module is supposed to send a DENM over a WiFi interface
    that is in OCB Mode
    """
    _json_message = 0
    _mqtt_client = 0
    mqtt_topic= ''
    json_file = ''

    def __init__(self, type = str) -> None:
        super().__init__()
        if type == "cam":
            self.set_cam()
        elif type == "denm":
            self.set_denm()
        else:
            print("Error: Message not found. Exiting!")
            #How to exit at this stage?

        self.load_json(self.json_file)

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to send DENM in OCB mode",
            dependencies=["paho.mqtt", "json", "jsonschema"],
            tags=["WIFI", "OCB", "ITS-G5", "DENM", "CAM"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        Defining the required ressources for this module
        This module depends on a configured WiFi interface that is joined an ocb channel
        """
        return [OcbInterface, MqttInstance]

    def run(self, inputs: Tuple[OcbInterface, MqttInstance]) -> None:
        """
        Sends the selected message
        """
        _, mqtt_broker = inputs
        self.connect_mqtt(mqtt_broker.ip, mqtt_broker.port)
        self.send_message()

    def load_json(self, rel_filepath: str) -> None:
        """
        Loads the json file for the message
        """
        curr_dir = os.path.dirname(__file__)
        filename = os.path.join(curr_dir, rel_filepath)
        with open(filename, encoding='UTF-8') as json_message_fd:
            self._json_message = json.load(json_message_fd)

    def connect_mqtt(self, ip, port) -> None:
        """
        Connects to an mqtt server.
        Needs to be started first!
        """
        self._mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self._mqtt_client.connect(ip, port, 60)

    def send_message(self) -> None:
        """
        Sends the message to the mqtt server
        """
        json_message = json.dumps(self._json_message)
        self._mqtt_client.publish(self.mqtt_topic, json_message)

    def set_cam(self):
        self.json_file = 'its_g5_messages/in_cam_full.json'
        self.mqtt_topic = 'vanetza/in/cam_full'

    def set_denm(self):
        self.json_file = 'its_g5_messages/in_denm.json'
        self.mqtt_topic = 'vanetza/in/denm'

    def modifiy_message(self, keys: List , value: str = ''):
        """
        Given the right keys, modify the message as you like :)
        """
        # Return type of data is a pointer (not immediately visible)
        data = reduce(operator.getitem, keys[:-1], self._json_message)[keys[-1]]
        reduce(operator.getitem, keys[:-1], self._json_message)[keys[-1]] = type(data)(value)
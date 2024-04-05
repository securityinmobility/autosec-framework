"""
Module for sending a DENM. (Decentralized Environmental Notification Messages)
"""
import os
from typing import List
import json
#import jsonschema
import paho.mqtt.client as mqtt
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.modules.wlan_p.ocb_join import OcbModeJoin


def load_module() -> List[AutosecModule]:
    """
    Load module
    """
    return [SendDenm()]

class SendDenm(AutosecModule):
    """
    This module is supposed to send a DENM over a WiFi interface
    that is in OCB Mode
    """
    _json_message = 0
    _mqtt_client = 0

    def __init__(self) -> None:
        super().__init__()
        self.load_json('its_g5_messages/in_denm.json')

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to send DENM in OCB mode",
            dependencies=["paho.mqtt", "json", "jsonschema"],
            tags=["WIFI", "OCB", "ITS-G5", "DENM"]
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
        return [OcbModeJoin]

    def run(self, inputs: List[AutosecRessource] = None) -> None:
        """
        Send a DENM
        """
        self.connect_mqtt()
        self.send_message()


    def load_json(self, rel_filepath: str) -> None:
        """
        Loads the json file for the message
        """
        curr_dir = os.path.dirname(__file__)
        filename = os.path.join(curr_dir, rel_filepath)
        with open(filename, encoding='UTF-8') as json_message_fd:
            self._json_message = json.load(json_message_fd)

    def connect_mqtt(self) -> None:
        """
        Connects to an mqtt server.
        Needs to be started first!
        """
        self._mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self._mqtt_client.connect("127.0.0.1", 1883, 60)

    def send_message(self):
        """
        Sends the message to the mqtt server
        """
        json_message = json.dumps(self._json_message)
        self._mqtt_client.publish("vanetza/in/denm", json_message)

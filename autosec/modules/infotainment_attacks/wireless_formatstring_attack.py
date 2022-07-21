"""
Wireless formatstring attack module
"""
import logging
from typing import List, Union, Type

from autosec.core.UserInteraction import UserInteraction
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation, AutosecExpectedMetrics
from autosec.core.commandLineInteraction import CommandLineInteraction
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.infotainment_attacks import WirelessFormatstringResult
from autosec.core.ressources.serial import COMPort
from utils.arduino import FormatstringProtocol

__author__: str = "Michael Weichenrieder"


class WirelessFormatstringAttack(AutosecModule):
    """
    Wireless formatstring attack module
    """

    # Payload dictionary with descriptions
    payloads: {str, str} = {
        "%s": "Interprets the next 4 bytes as char pointer and displays it as string",
        "%p": "Interprets the next 4 bytes as pointer and displays it with an \"0x\"-prefix",
        "%x": "Displays the next 4 bytes as hex",
        "%o": "Displays the next 4 bytes as octal",
        "%d": "Interprets and displays the next 4 bytes as decimal",
        "%i": "Interprets and displays the next 4 bytes as decimal",
        "%u": "Interprets and displays the next 4 bytes as unsigned decimal",
        "%hi": "Interprets and displays the next 2 bytes as short",
        "%hu": "Interprets and displays the next 2 bytes as unsigned short",
        "%c": "Interprets and displays the next byte as character",
        "%lf": "Interprets and displays the next 8 bytes as long double",
        "%f": "Interprets and displays the next 4 bytes as floating point number",
        "%e": "Interprets and displays the next 4 bytes as floating point number in scientific notation",
        "%E": "Interprets and displays the next 4 bytes as floating point number in scientific notation",
        "%%": "Displays as a single percent symbol"
    }

    def __init__(self):
        """
        Initialize logger in constructor
        """
        super().__init__()
        self._logger = logging.getLogger("autosec.modules.infotainment_attacks.wireless_formatstring_attack")
        self._logger.setLevel(logging.INFO)

    def get_info(self) -> AutosecModuleInformation:
        """
        :return: Basic info of the module
        """
        return AutosecModuleInformation(
            name=type(self).__name__,
            description="Checks a target for bluetooth and wlan formatstring vulnerabilities",
            dependencies=["pyserial"],
            tags=["wireless", "wlan", "bluetooth", "formatstring"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        :return: Output resource examples
        """
        return [
            WirelessFormatstringResult(
                wireless_type="bluetooth",
                formatstring="%p",
                success=True
            ),
            WirelessFormatstringResult(
                wireless_type="wlan",
                formatstring="%p",
                success=True
            ),
            WirelessFormatstringResult(
                wireless_type="bluetooth",
                formatstring="%s",
                success=False
            ),
            WirelessFormatstringResult(
                wireless_type="wlan",
                formatstring="%s",
                success=False
            )
        ]

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        :return: Required input resource example
        """
        return [
            COMPort(
                port="COM5"
            )
        ]

    def can_run(self, inputs: List[AutosecRessource]) -> Union[bool, AutosecExpectedMetrics]:
        """
        :return: If the attack can run and metrics if it can
        """
        if super().can_run(inputs):
            return AutosecExpectedMetrics(
                can_run=True,
                expected_runtime=len(self.payloads) * 2 * 30,  # Based on user interaction time (guess: 30 seconds)
                expected_success=.2  # Pretty unsure, not enough data
            )
        return False

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        """
        Run the attack

        :param inputs: The inputs (COMPort)
        :return: The results (WirelessFormatstringResult)
        """
        # Get com port from input resources
        com_port: str = self.get_ressource(inputs, Type[COMPort]).get_port()

        # Init serial connection
        formatstring_protocol: FormatstringProtocol = FormatstringProtocol(port=com_port)
        user_interaction: UserInteraction = CommandLineInteraction()

        # Success summary
        results: [WirelessFormatstringResult] = []
        vulnerabilities: int = 0

        # Test all payloads
        payload_count: int = len(self.payloads)
        payload_counter: int = 0
        for formatstring, description in self.payloads.items():

            # Try to load payload
            if not formatstring_protocol.set_formatstring(formatstring):
                raise Exception("Serial failed to respond correctly")
            payload_counter += 1

            # Display stats
            user_interaction.feedback(f"Payload {payload_counter}/{payload_count} loaded:\n"
                                      f"- Formatstring: {formatstring}\n"
                                      f"- Description: {description}")

            # Request success from user
            for wireless_type in ["bluetooth", "wlan"]:
                user_interaction.setQuestion(
                    f"- What is displayed via {wireless_type}? (1) the described data, (2) formatstring, (3) skip")
                success: int = user_interaction.integerAnswer()
                if success in [1, 2]:
                    if success == 1:
                        vulnerabilities += 1
                        self._logger.info(
                            f"Formatstring {formatstring} revealed a vulnerability via {wireless_type} name")
                    results.append(
                        WirelessFormatstringResult(
                            wireless_type=wireless_type,
                            formatstring=formatstring,
                            success=True if success == 1 else False)
                    )

        # Return summary
        self._logger.info(f"'Wireless formatstring attack done. Successful formatstring tests: {vulnerabilities}")
        return results

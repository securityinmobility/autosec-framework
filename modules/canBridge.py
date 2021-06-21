from core.autosecModule import AutosecModule
from scapy.all import *

def load_module():
    return canBridge()


class canBridge(AutosecModule):

    def __init__(self):
        super.__init__()

        self.interfaces = dict(
            primaryInterface = dict(name = "primaryInterface",
                required = True,
                default = None,
                unit = "SocketCAN Device Name",
                range = None,
                value = None),
            secondaryInterface = dict(name = "secondaryInterface",
                required = True,
                default = None,
                unit = "SocketCAN Device Name",
                range = None,
                value = None)
            )   
        self.intercept = [(0x7af, 
            lambda data: b'\x03\x04\x05',
            None, 
            lambda data: b'\x06\x07\x08')]     #list to carry the messages to be intercepted; ID IF1, Answer IF1, ID IF2, Answer IF2
        load_layer("can")
        load_contrib("cansocket")

        self.primaryInterface = CANsocket(channep = "vcan0")




    def getInfo(self):
        return(dict(
            name = "canBridge",
            source = "autosec",
            type = "mitm",
            interface = "CAN",
            description = "Module to perform MITM CAN attacks with two CAN interfaces"))

    def getOptions(self):
        return self.interfaces #Vielleicht nur eine Kopie, damit setter genutzt werden muss?

    def setOptions(self, options):
        return super().setOptions(options)

    def run(self):
        return super().run()

    def forwardMessages(pkt):
        # Sobald Daten auf einem Kanal ankommen prüfen, ob diese verändert werden müssen, sonst weiterleiten
        return pkt

    def interceptMessage(filterRule, data):
        # Abgefangene Nachrichten verändern und dann weiterleiten
        # Nachricht wurde aufgrund der ID oder des Inhalts identifiziert, nun muss der Inhalt auf eine Nachricht auf eine Antwort je Interface abgebildet werden
        data = b'\x00\x01\x02'

        primaryAnswer = filterRule[1](data)
        secondaryAnswer = filterRule[3](data)

        return primaryAnswer, secondaryAnswer

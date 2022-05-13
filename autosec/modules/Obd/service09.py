'''
Decodes the VIN number of a vehicle and gives additional information
such as the country, manufacturer, region and years.
'''
import logging

from scapy.all import load_contrib, ISOTPSocket, ISOTP
from scapy.main import load_layer
from autosec.core.ressources.can import IsoTPService
from vininfo import Vin

logger = logging.getLogger("autosec.modules.Obd.service09")
logger.setLevel(logging.DEBUG)

def get_vin(interface):
    '''
    Gets the VIN number from a CAN message and decodes it.
    '''
    load_contrib("isotp")
    load_layer("can")

    try:
        socket = IsoTPService(interface, tx_id=0x7E0, tx_id=0x7E8).get_socket()
        msg = ISOTP(data=b'\x09\x02')
        socket.send(msg)
    except OSError as err:
        logger.warning(f"Message could not be sent {err}")

    message = socket.recv(x=1) # TODO: figure out why timeout doesnt work
    message_bytes = bytes(message)

    vin_dict = {}
    raw_data = {}
    if message is not None:
        vin = Vin(str(message_bytes[3:], "utf-8"))
        vin_dict = {
            "VIN": str(vin),
            "Country": vin.country,
            "Manufacturer": vin.manufacturer,
            "Region": vin.region,
            "Years": vin.years
        }
        raw_data = {format(message.src, "02X")+ "#" + str(format(len(msg), "02X"))+
                    " " +msg.data.hex(" "):
                    format(message.dst, "02X") + "#" + format(len(message), "02X") + " " +
                    " ".join(format(x, "02X") for x in message_bytes)}
        logger.debug(f"\nVIN: {vin}\nCountry: {vin.country}\nManufacturer: {vin.manufacturer}"
                    f"\nRegion: {vin.region}\nYears: {vin.years}")
    else:
        logger.warning("Message could not be received")
    socket.close()
    return vin_dict, raw_data

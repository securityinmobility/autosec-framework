'''
Decodes the VIN number of a vehicle and gives additional information
such as the country, manufacturer, region and years.
'''
import logging
import isotp

from vininfo import Vin

logger = logging.getLogger("autosec.modules.Obd.service09")
logger.setLevel(logging.INFO)

def get_vin():
    '''
    Gets the VIN number from a CAN message and decodes it.
    '''
    socket = isotp.socket()
    # Configuring the sockets.
    socket.set_fc_opts(stmin=5, bs=10)
    #s.set_general_opts(...)
    #s.set_ll_opts(...)

    try:
        socket.bind("vcan0", isotp.Address(rxid=0x7E8, txid=0x7DF))
        socket.send(b"\x09\x02")
    except OSError as err:
        logger.warning(f"Message could not be sent {err}")

    msg = socket.recv()
    if msg is not None:
        vin = Vin(str(msg[3:], "utf-8"))
        logger.info(f"\nVIN: {vin}\nCountry: {vin.country}\nManufacturer: {vin.manufacturer}"
                    f"\nRegion: {vin.region}\nYears: {vin.years}")
    else:
        logger.warning("Message could not be received")

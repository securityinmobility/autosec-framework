import isotp
import logging

from vininfo import Vin

logger = logging.getLogger("autosec.modules.service09")
logger.setLevel(logging.INFO)

def getVIN():
    s = isotp.socket()
    # Configuring the sockets.
    s.set_fc_opts(stmin=5, bs=10)
    #s.set_general_opts(...)
    #s.set_ll_opts(...)

    try:
        s.bind("vcan0", isotp.Address(rxid=0x7E8, txid=0x7DF))
        s.send(b"\x09\x02")
    except:
        logger.warning("Message could not be sent")

    try:
        msg = s.recv()
        vin = Vin(str(msg[3:], "utf-8"))
    except:
        logger.warning("Message could not be received")


    logger.info(f"\nVIN: {vin}\nCountry: {vin.country}\nManufacturer: {vin.manufacturer}\nRegion: {vin.region} \nYears: {vin.years}")

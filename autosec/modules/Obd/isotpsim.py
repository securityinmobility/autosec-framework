import logging

from scapy.all import *

conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}
load_contrib('cansocket')
load_contrib('isotp')

logger = logging.getLogger("autosec.modules.Obd.isotpsim")
logger.setLevel(logging.INFO)

try:
    socks = [ISOTPSocket("vcan0", sid=0x700, did=0x701, padding=False, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x709, did=0x707, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x71c, did=0x788, padding=False, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x799, did=0x745, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x7aa, did=0x703, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x7cc, did=0x7bb, padding=False, basecls=ISOTP)]
    logger.info("ISOTP Endpoints initialized.")
    while True: time.sleep(100) 
except KeyboardInterrupt:
    logger.info("Received keyboard interrupt, quitting.")
    for count, socket in enumerate(socks):
        socks[count].close()

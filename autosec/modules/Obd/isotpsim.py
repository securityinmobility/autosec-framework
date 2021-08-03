import logging

from scapy.all import *

conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}
load_contrib('cansocket')
load_contrib('isotp')

logger = logging.getLogger("autosec.modules.Obd.isotpsim")
logger.setLevel(logging.INFO)

try:
    # Normal ID Sockets 11-bit ID
    socks = [ISOTPSocket("vcan0", sid=0x700, did=0x701, padding=False, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x709, did=0x707, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x71c, did=0x788, padding=False, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x799, did=0x745, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x7aa, did=0x703, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x7cc, did=0x7bb, padding=False, basecls=ISOTP),
    # Extended ID Sockets 29-bit ID
    ISOTPSocket("vcan0", sid=0x705, did=0x712, extended_addr=0x41, extended_rx_addr=0x41, padding=False, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x713, did=0x707, extended_addr=0x42, extended_rx_addr=0x55, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x73c, did=0x777, extended_addr=0x43, extended_rx_addr=0x49, padding=False, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x789, did=0x755, extended_addr=0x44, extended_rx_addr=0x58, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x7ee, did=0x702, extended_addr=0x45, extended_rx_addr=0x50, padding=True, basecls=ISOTP),
    ISOTPSocket("vcan0", sid=0x7ab, did=0x7cd, extended_addr=0x46, extended_rx_addr=0x59, padding=False, basecls=ISOTP),]
    logger.info("ISOTP Endpoints initialized.")
    while True: time.sleep(100) 
except KeyboardInterrupt:
    logger.info("Received keyboard interrupt, quitting.")
    for count, socket in enumerate(socks):
        socks[count].close()
        logger.info(f"Closed socket: {socks[count]}")

'''
Scans for ISO-TP Endpoints
'''
import logging

from scapy.all import *

logger = logging.getLogger("autosec.modules.Obd.isotp_endpoints")
logger.setLevel(logging.INFO)

conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}
load_contrib('cansocket')
load_contrib('isotp')

socks = ISOTPScan(CANSocket("vcan0"), range(0x700, 0x7ff), can_interface="vcan0",
                            output_format="text", verbose=True)
                            # TODO: 29-bit identifier
logger.info(socks)

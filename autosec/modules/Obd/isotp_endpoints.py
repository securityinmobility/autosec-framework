'''
Scans for ISO-TP Endpoints
'''
import logging

from scapy.all import conf, load_contrib

def scan_endpoints(interface):
    '''
    Scan for ISO-TP Endpoints
    '''
    logger = logging.getLogger("autosec.modules.Obd.isotp_endpoints")
    logger.setLevel(logging.INFO)

    conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
    conf.contribs['CANSocket'] = {'use-python-can': False}
    load_contrib('cansocket')
    load_contrib('isotp')

    logger.info("Starting scan for normal IDs...")
    socks = scan_endpoints_normal(interface)
    logger.info("Scan for normal IDs done.")
    logger.info(socks)

    logger.info("Starting scan for extended IDs...")
    socks_extended = scan_endpoints_extended(interface)
    logger.info("Scan for extended IDs done.")
    logger.info(socks_extended)

def scan_endpoints_normal(interface):
    socks = ISOTPScan(CANSocket(interface), range(0x700, 0x7ff), can_interface="vcan0",
                                output_format="text", verbose=True)
    return socks

def scan_endpoints_extended(interface):
    socks_extended = ISOTPScan(CANSocket(interface), range(0x700, 0x7ff), can_interface="vcan0",
                                extended_addressing=True, extended_scan_range=range(0x40, 0x5a),
                                output_format="text", verbose=True)
    return socks_extended

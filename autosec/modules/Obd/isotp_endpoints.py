'''
Scans for ISO-TP Endpoints
'''
import logging

from scapy.all import conf, load_contrib

logger = logging.getLogger("autosec.modules.Obd.isotp_endpoints")
logger.setLevel(logging.INFO)

def scan_endpoints(interface, scan_type, scan_range, extended_range):
    '''
    Scan for ISO-TP Endpoints
    '''
    conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
    conf.contribs['CANSocket'] = {'use-python-can': False}
    load_contrib('cansocket')
    load_contrib('isotp')

    if scan_type == "normal":
        scan_endpoints_normal(interface, scan_range)
    elif scan_type == "extended":
        scan_endpoints_extended(interface, scan_range, extended_range)
    else:
        scan_endpoints_normal(interface, scan_range)
        scan_endpoints_extended(interface, scan_range, extended_range)

def scan_endpoints_normal(interface, scan_range):
    '''
    Scan for ISO-TP Endpoints
    '''
    logger.info("Starting scan for normal IDs...")
    socks = ISOTPScan(CANSocket(interface), scan_range, can_interface="vcan0",
                                output_format="text", verbose=True)
    logger.info("Scan for normal IDs done.")
    logger.info(socks)

def scan_endpoints_extended(interface, scan_range, extended_range):
    '''
    Scan for Extended ISO-TP Endpoints
    '''
    logger.info("Starting scan for extended IDs...")
    socks_extended = ISOTPScan(CANSocket(interface), scan_range, can_interface="vcan0",
                                extended_addressing=True, extended_scan_range=extended_range,
                                output_format="text", verbose=True)
    logger.info("Scan for extended IDs done.")
    logger.info(socks_extended)

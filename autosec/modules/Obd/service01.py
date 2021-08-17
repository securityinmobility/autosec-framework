'''
This file interprets some messages received from the OBD-II service 01.
'''
import logging
import can

from tabulate import tabulate

logger = logging.getLogger("autosec.modules.Obd.service01")
logger.setLevel(logging.DEBUG)

def _send_message(bus, msg, pid):
    '''
    Sends the given message over the given CAN Bus
    '''
    try:
        bus.send(msg)
        logger.debug(f"Message sent on {bus.channel_info}: Running PID 0x{pid:02X}")
    except can.CanError:
        logger.warning("Message NOT sent")

def _receive_message(bus):
    '''
    Receives a message from the CAN Bus
    '''
    message = bus.recv(10.0)
    if message is None:
        logger.error("Timeout occured, no message.")
        return None
    while message.arbitration_id != 2024:
        message = bus.recv()
        break
    return message

def _fill_table(byte_list, byte_1, byte_2, bit, tests):
    '''
    Helper function for get_mil_status()
    '''
    tests_table = {}
    if len(tests) == 3:
        for offset, name in enumerate(tests):
            tests_table[name] = {}
            if byte_list[byte_1][5 + offset] == "1":
                supported = "supported"
            tests_table[name]["Availability"] = supported
            if byte_list[byte_2][3 - offset] == "0":
                ready = "ready"
            tests_table[name]["Completeness"] = ready

            ready = "not ready"
            supported = "not supported"
    else:
        for offset, name in enumerate(tests):
            tests_table[name] = {}
            if byte_list[byte_1][bit + offset] == "1":
                supported = "supported"
            tests_table[name]["Availability"] = supported
            if byte_list[byte_2][bit + offset] == "0":
                ready = "ready"
            tests_table[name]["Completeness"] = ready

            ready = "not ready"
            supported = "not supported"

    return tests_table

def _printable_table(tests, tests_table):
    '''
    Returns a table for tabulate
    '''
    printable_table = []
    for test in tests:
        availability = tests_table[test]["Availability"]
        comepleteness = tests_table[test]["Completeness"]
        printable_table += [[test, availability, comepleteness]]
    return printable_table

def get_supported_pid(interface, pid):
    '''
    PID 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0
    Provides the available PIDs of the ECU
    '''
    valid = [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0]
    if pid not in valid:
        raise ValueError("Valid PIDs:", [hex(i) for i in valid])
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg_pid = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, pid], is_extended_id=False
    )

    _send_message(bus, msg_pid, pid)

    message = _receive_message(bus)

    # convert bytearray in binary
    if message is None:
        return None

    byte_list = []
    for byte in message.data:
        byte_list.append(bin(byte)[2:].zfill(8))

    switcher = {
        0x00: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x20],
        0x20: [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F, 0x40],
        0x40: [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
            0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
            0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
            0x5C, 0x5D, 0x5E, 0x5F, 0x60],
        0x60: [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
            0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
            0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B,
            0x7C, 0x7D, 0x7E, 0x7F, 0x80],
        0x80: [0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92,
            0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
            0x9C, 0x9D, 0x9E, 0x9F, 0xA0],
        0xA0: [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
            0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
            0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
            0xBC, 0xBD, 0xBE, 0xBF, 0xC0],
        0xC0: [0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
            0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2,
            0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB,
            0xDC, 0xDD, 0xDE, 0xDF, 0xE0],
    }
    pid_list = switcher.get(pid, "Invalid")
    supported_pids = []
    i = 0
    for j in range(3,7):
        for bit in byte_list[j]:
            if bit == "1":
                supported_pids.append(pid_list[i])
            i += 1
    switcher = {
        0x00: "[01 - 20]",
        0x20: "[21 - 40]",
        0x40: "[41 - 60]",
        0x60: "[61 - 80]",
        0x80: "[81 - A0]",
        0xA0: "[A1 - C0]",
        0xC0: "[C1 - E0]",
    }
    curr_pid = switcher.get(pid, "Invalid")
    logger.debug(f"List of supported PIDs {curr_pid}:\n%s",
                ["0x{:02X}".format(i) for i in supported_pids])

    return supported_pids

def get_mil_status(interface, pid):
    '''
    PID 01
    Monitor status sice DTCs cleared. Includes malfunction indicator lamp status
    and number of DTCs.
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x01], is_extended_id=False
    )

    _send_message(bus, msg, pid)

    message = _receive_message(bus)

    mil_info = {}
# convert bytearray in binary
    if message is None:
        return None

    byte_list = []
    for byte in message.data:
        byte_list.append(bin(byte)[2:].zfill(8))

# If the first Bit is 1 then the MIL is on
    state = "OFF"
    if byte_list[3][0] == "1":
        state = "ON"
    logger.debug(f"MIL: {state}")
    mil_info["Malfunction indicator lamp"] = state

# Number of DTCs
    dtc_count = int(byte_list[3][1:],2)
    logger.debug(f"Number of emission-related DTCs: {dtc_count}")
    mil_info["Number of emission-related DTCs"] = dtc_count

# Availablity and Completeness of On-Board-Tests
    headers = ["On-Board-Test", "Availability", "Completeness"]
    tests = ["Misfire monitoring", "Fuel system monitoring",
                    "Comprehensive component monitoring"]

    tests_table = _fill_table(byte_list, 4, 4, None, tests)
    mil_info = {**mil_info, **tests_table}
    logger.debug("\n" + tabulate(_printable_table(tests, tests_table), headers=headers,
                    tablefmt="pretty", stralign="left"))
    ignition = {
        "0": "Spark ignition (Otto/Wankel engine)",
        "1": "Compression ignition (Diesel engine)"
    }
    logger.debug("------------On-Board-Tests that are ignition specific------------")
    logger.debug(f"Ignition: {ignition[byte_list[4][4]]}")
    mil_info["Ignition"] = ignition[byte_list[4][4]]

    if byte_list[4][4] == "0":
        tests = ["EGR system montioring", "Oxygen sensor heater monitoring",
            "Oxygen sensor monitoring", "A/C system refrigerant monitoring",
            "Secondary air system monitoring", "Evaporative system monitoring",
            "Heated catalyst monitoring", "Catalyst monitoring"]

        tests_table = _fill_table(byte_list, 5, 6, 0, tests)
        mil_info = {**mil_info, **tests_table}
        logger.debug("\n" + tabulate(_printable_table(tests, tests_table), headers,
                    tablefmt="pretty", stralign="left"))
    else:
        tests = ["EGR and/or VVT System", "PM filter monitoring",
            "Exhaust gas sensor monitoring", "ISO/SAE Reserved C4/D4",
            "Boost pressure monitoring", "ISO/SAE Reserved C2/D2",
            "NOx/SCR aftertreatment monitoring", "NMHC catalyst monitoring"]

        tests_table = _fill_table(byte_list, 5, 6, 0, tests)
        mil_info = {**mil_info, **tests_table}
        logger.debug("\n" + tabulate(_printable_table(tests, tests_table), headers,
                    tablefmt="pretty", stralign="left"))

    #logger.debug(mil_info)

    return mil_info

def get_fuelsystem_status(interface, pid):
    '''
    PID 03
    Fuel system status
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x03], is_extended_id=False
    )

    _send_message(bus, msg, pid)

    message = _receive_message(bus)

    fs_info = {}
    switcher = {
        0: "The motor is off",
        1: "Open loop due to insufficient engine temperature",
        2: "Closed loop, using oxygen sensor feedback to determine fuel mix",
        4: "Open loop due to engine load OR fuel cut due to deceleration",
        8: "Open loop due to system failure",
        16: "Closed loop, using at least one oxygen sensor but there is a "
            "fault in the feedbacksystem",
    }
    fs_status = switcher.get(message.data[3], "Invalid Response")
    fs_info["Fuel system #1"] = fs_status
    logger.debug(f"Fuel system #1:\n{fs_status}")

    # If the 2nd byte is exists, then there are two fuel systems
    # that are identically encoded
    if len(message.data) > 4:
        switcher = {
        0: "The motor is off",
        1: "Open loop due to insufficient engine temperature",
        2: "Closed loop, using oxygen sensor feedback to determine fuel mix",
        4: "Open loop due to engine load OR fuel cut due to deceleration",
        8: "Open loop due to system failure",
        16:"Closed loop, using at least one oxygen sensor but there is a "
        "fault in the feedback system",
    }
    fs_status2 = switcher.get(message.data[4], "Invalid Response")
    fs_info["Fuel system #2"] = fs_status2
    logger.debug(f"Fuel system #2:\n{fs_status2}")

    #logger.debug(fs_info)
    return fs_info

def get_engine_load(interface, pid):
    '''
    PID 04
    Calculated engine load
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x04], is_extended_id=False
    )

    _send_message(bus, msg, pid)

    message = _receive_message(bus)

    eload_info = {}
    load_value = round(message.data[3] / 2.55, 2)
    eload_info["Calculated Engine load[%]"] = load_value
    logger.debug(f"Calculated Engine load: {load_value} %")

    #logger.debug(eload_info)
    return eload_info

def get_engine_coolant_temp(interface, pid):
    '''
    PID 05
    Engine coolant temperature
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x05], is_extended_id=False
    )

    _send_message(bus, msg, pid)

    message = _receive_message(bus)

    ecoolant_info = {}
    ecoolant_temp = round(message.data[3] - 40, 2)
    ecoolant_info["Engine Coolant Temperature[°C]"] = ecoolant_temp
    logger.debug(f"Engine Coolant Temperature: {ecoolant_temp} °C")

    #logger.debug(ecoolant_info)
    return ecoolant_info

def get_engine_speed(interface, pid):
    '''
    PID 0C
    Engine speed
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x0C], is_extended_id=False
    )

    _send_message(bus, msg, pid)

    message = _receive_message(bus)

    espeed_info = {}
    speed = round(((256 * message.data[3]) + message.data[4]) / 4, 2)
    espeed_info["Engine Speed[RPM]"] = speed
    logger.debug(f"Engine speed: {speed} RPM")

    #logger.debug(espeed_info)
    return espeed_info

def get_vehicle_speed(interface, pid):
    '''
    PID 0D
    Vehicle Speed
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x0D], is_extended_id=False
    )

    _send_message(bus, msg, pid)

    message = _receive_message(bus)

    vspeed_info = {}
    speed = message.data[3]
    vspeed_info["Vehicle speed[km/h]"] = speed
    logger.debug(f"Vehicle speed: {speed} km/h")

    #logger.debug(vspeed_info)
    return vspeed_info

def get_obd_standard(interface, pid):
    '''
    PID 1C
    Get OBD standard this vehicle conforms to
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x1C], is_extended_id=False
    )

    _send_message(bus, msg, pid)

    message = _receive_message(bus)

    obdstd_info = {}
    switcher = {
        1: "OBD-II as defined by the CARB",
        2: "OBD as defined by the EPA",
        3: "OBD and OBD-II",
        4: "OBD-I",
        5: "Not OBD compliant",
        6: "EOBD (Europe)",
        7: "EOBD and OBD-II",
        8: "EOBD and OBD",
        9: "EOBD, OBD, OBD-II",
        10: "JOBD (Japan)",
        11: "JOBD and OBD-II",
        12: "JOBD and EOBD",
        13: "JOBD, EOBD, and OBD-II",
        14: "Reserved",
        15: "Reserved",
        16: "Reserved",
        17: "Engine Manufacturer Diagnostics (EMD)",
        18: "Engine Manufacturer Diagnostics Enhanced (EMD+)",
        19: "Heavy Duty On-Board Diagnostics (Child/Partial) (HD OBD-C)",
        20: "Heavy Duty On-Board Diagnostics (HD OBD)",
        21: "World Wide Harmonized OBD (WWH OBD)",
        22: "Reserved",
        23: "Heavy Duty Euro OBD Stage I without NOx control (HD EOBD-I)",
        24: "Heavy Duty Euro OBD Stage I with NOx control (HD EOBD-I N)",
        25: "Heavy Duty Euro OBD Stage II without NOx control (HD EOBD-II)",
        26: "Heavy Duty Euro OBD Stage II with NOx control (HD EOBD-II N)",
        27: "Reserved",
        28: "Brazil OBD Phase 1 (OBDBr-1)",
        29: "Brazil OBD Phase 2 (OBDBr-2)",
        30: "Korean OBD (KOBD)",
        31: "India OBD I (IOBD I)",
        32: "India OBD II (IOBD II)",
        33: "Heavy Duty Euro OBD Stage VI (HD EOBD-IV)",
    }
    obdstd = switcher.get(message.data[3], "Reserved / Not available for assignment")

    obdstd_info["Vehicle OBD Standard"] = obdstd
    logger.debug(f"This vehicle conforms to the {obdstd} standard.")

    #logger.debug(obdstd_info)
    return obdstd_info

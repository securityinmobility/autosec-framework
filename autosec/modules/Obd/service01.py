'''
This file interprets some messages received from the OBD-II service 01.
'''
import logging
import can

from tabulate import tabulate

logger = logging.getLogger("autosec.modules.service01")
logger.setLevel(logging.DEBUG)

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

    try:
        bus.send(msg_pid)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
            # convert bytearray in binary
                byte_list = []
                for byte in message.data:
                    binary = bin(byte)[2:].zfill(8)
                    byte_list.append(binary)
                switcher = {
                    0x00: ["01", "02", "03", "04", "05", "06", "07", "08", "09",
                        "0A", "0B", "0C", "0D", "0E", "0F", "10", "11", "12",
                        "13", "14", "15", "16", "17", "18", "19", "1A", "1B",
                        "1C", "1D", "1E", "1F", "20"],
                    0x20: ["21", "22", "23", "24", "25", "26", "27", "28", "29",
                        "2A", "2B", "2C", "2D", "2E", "2F", "30", "31", "32",
                        "33", "34", "35", "36", "37", "38", "39", "3A", "3B",
                        "3C", "3D", "3E", "3F", "40"],
                    0x40: ["41", "42", "43", "44", "45", "46", "47", "48", "49",
                        "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52",
                        "53", "54", "55", "56", "57", "58", "59", "5A", "5B",
                        "5C", "5D", "5E", "5F", "60"],
                    0x60: ["61", "62", "63", "64", "65", "66", "67", "68", "69",
                        "6A", "6B", "6C", "6D", "6E", "6F", "70", "71", "72",
                        "73", "74", "75", "76", "77", "78", "79", "7A", "7B",
                        "7C", "7D", "7E", "7F", "80"],
                    0x80: ["81", "82", "83", "84", "85", "86", "87", "88", "89",
                        "8A", "8B", "8C", "8D", "8E", "8F", "90", "91", "92",
                        "93", "94", "95", "96", "97", "98", "99", "9A", "9B",
                        "9C", "9D", "9E", "9F", "A0"],
                    0xA0: ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9",
                        "AA", "AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2",
                        "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB",
                        "BC", "BD", "BE", "BF", "C0"],
                    0xC0: ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9",
                        "CA", "CB", "CC", "CD", "CE", "CF", "D0", "D1", "D2",
                        "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB",
                        "DC", "DD", "DE", "DF", "E0"],
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
                logger.info(f"List of supported PIDs {curr_pid}:\n {supported_pids}")

    except can.CanError:
        logger.warning("Message NOT sent")

def get_mil_status(interface):
    '''
    PID 01
    Monitor status sice DTCs cleared. Includes malfunction indicator lamp status
    and number of DTCs.
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x01], is_extended_id=False
    )

    try:
        bus.send(msg)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
            # convert bytearray in binary
                byte_list = []
                for byte in message.data:
                    binary = bin(byte)[2:].zfill(8)
                    byte_list.append(binary)

            # If the first Bit is 1 then the MIL is on
                if byte_list[3][0] == "1":
                    state = "ON"
                else:
                    state = "OFF"
                logger.info(f"MIL: {state}")

            # Number of DTCs
                dtc_count = int(byte_list[3][1:],2)
                logger.info(f"Number of emission-related DTCs: {dtc_count}")

            # Availablity and Completeness of On-Board-Tests
                misfire = "not supported"
                fuel = "not supported"
                components = "not supported"
                misfire_test = "not ready"
                fuel_test = "not ready"
                components_test = "not ready"

                if byte_list[4][7] == "1":
                    misfire = "supported"
                if byte_list[4][6] == "1":
                    fuel = "supported"
                if byte_list[4][5] == "1":
                    components = "supported"
                if byte_list[4][4] == '1':
                    ignition = "Compression ignition (Diesel engine)"
                    ign = 1
                else:
                    ignition = "Spark ignition (Otto/Wankel engine)"
                    ign = 0
                if byte_list[4][3] == "0":
                    misfire_test = "ready"
                if byte_list[4][2] == "0":
                    fuel_test = "ready"
                if byte_list[4][1] == "0":
                    components_test = "ready"


                logger.info("\n" + tabulate([["Misfire monitoring",
                                misfire, misfire_test],
                                ["Fuel system monitoring",
                                fuel, fuel_test],
                                ["Comprehensive component monitoring",
                                components, components_test]],
                                ["On-Board-Test", "Availability", "Completeness"],
                                tablefmt="pretty", stralign="left"))
                logger.info("------------On-Board-Tests that are ignition specific------------")
                logger.info(f"Ignition: {ignition}")

                catalyst = "not supported"
                catalyst_test = "not ready"
                heated_catalyst = "not supported"
                heated_catalyst_test = "not ready"
                ev_system = "not supported"
                ev_system_test = "not ready"
                sec_air_sytem = "not supported"
                sec_air_sytem_test = "not ready"
                ac_refrigirant = "not supported"
                ac_refrigirant_test = "not ready"
                oxygen_sensor = "not supported"
                oxygen_sensor_test = "not ready"
                oxygen_sensor_heater = "not supported"
                oxygen_sensor_heater_test = "not ready"
                egr_system = "not supported"
                egr_system_test = "not ready"

                if byte_list[5][7] == "1":
                    catalyst = "supported"
                if byte_list[5][6] == "1":
                    heated_catalyst = "supported"
                if byte_list[5][5] == "1":
                    ev_system = "supported"
                if byte_list[5][4] == "1":
                    sec_air_sytem = "supported"
                if byte_list[5][3] == "1":
                    ac_refrigirant = "supported"
                if byte_list[5][2] == "1":
                    oxygen_sensor = "supported"
                if byte_list[5][1] == "1":
                    oxygen_sensor_heater = "supported"
                if byte_list[5][0] == "1":
                    egr_system = "supported"
                if byte_list[6][7] == "0":
                    catalyst_test = "ready"
                if byte_list[6][6] == "0":
                    heated_catalyst_test = "ready"
                if byte_list[6][5] == "0":
                    ev_system_test = "ready"
                if byte_list[6][4] == "0":
                    sec_air_sytem_test = "ready"
                if byte_list[6][3] == "0":
                    ac_refrigirant_test = "ready"
                if byte_list[6][2] == "0":
                    oxygen_sensor_test = "ready"
                if byte_list[6][1] == "0":
                    oxygen_sensor_heater_test = "ready"
                if byte_list[6][0] == "0":
                    egr_system_test = "ready"

                if ign == 0:
                    logger.info("\n" + tabulate([["EGR System monitoring",
                                    egr_system, egr_system_test],
                                    ["Oxygen Sensor Heater monitoring",oxygen_sensor_heater,
                                    oxygen_sensor_heater_test],
                                    ["Oxygen Sensor monitoring", oxygen_sensor, oxygen_sensor_test],
                                    ["ISO/SAE reserved", "-", "-"],
                                    ["Secondary Air System monitoring", sec_air_sytem,
                                    sec_air_sytem_test],
                                    ["Evaporative System monitoring", ev_system, ev_system_test],
                                    ["Heated Catalyst monitoring", heated_catalyst,
                                    heated_catalyst_test],
                                    ["Catalyst monitoring", catalyst, catalyst_test]],
                                    ["On-Board-Test", "Availability", "Completeness"],
                                    tablefmt="pretty", stralign="left"))
                else:
                    logger.info("\n" + tabulate([["EGR and/or VVT System monitoring",
                                    egr_system, egr_system_test],
                                    ["PM filter monitoring",
                                    oxygen_sensor_heater, oxygen_sensor_heater_test],
                                    ["Exhaust Gas Sensor monitoring",
                                    oxygen_sensor, oxygen_sensor_test],
                                    ["ISO/SAE reserved", "-", "-"],
                                    ["Boost Pressure monitoring",
                                    sec_air_sytem, sec_air_sytem_test],
                                    ["ISO/SAE reserved", "-", "-"],
                                    ["NOx aftertreatment monitoring",
                                    heated_catalyst, heated_catalyst_test],
                                    ["NMHC catalyst monitoring",
                                    catalyst, catalyst_test]],
                                    ["On-Board-Test", "Availability", "Completeness"],
                                    tablefmt="pretty", stralign="left"))

    except can.CanError:
        logger.warning("Message NOT sent")

def get_fuelsystem_status(interface):
    '''
    PID 03
    Fuel system status
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x03], is_extended_id=False
    )

    try:
        bus.send(msg)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
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
                logger.info(f"Fuel system #1:\n{fs_status}")

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
                logger.info(f"Fuel system #2:\n{fs_status2}")

    except can.CanError:
        logger.warning("Message NOT sent")

def get_engine_load(interface):
    '''
    PID 04
    Calculated engine load
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x04], is_extended_id=False
    )

    try:
        bus.send(msg)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
                load_value = round(message.data[3] / 2.55, 2)
                logger.info(f"Calculated Engine load: {load_value} %")

    except can.CanError:
        logger.warning("Message NOT sent")

def get_engine_coolant_temp(interface):
    '''
    PID 05
    Engine coolant temperature
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x05], is_extended_id=False
    )

    try:
        bus.send(msg)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
                eng_temp = round(message.data[3] - 40, 2)
                logger.info(f"Engine Coolant Temperature: {eng_temp} °C")

    except can.CanError:
        logger.warning("Message NOT sent")

def get_engine_speed(interface):
    '''
    PID 0C
    Engine speed
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x0C], is_extended_id=False
    )

    try:
        bus.send(msg)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
                speed = round(((256 * message.data[3]) + message.data[4]) / 4, 2)
                logger.info(f"Vehicle speed: {speed} RPM")

    except can.CanError:
        logger.warning("Message NOT sent")

def get_vehicle_speed(interface):
    '''
    PID 0D
    Vehicle Speed
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x0D], is_extended_id=False
    )

    try:
        bus.send(msg)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
                speed = message.data[3]
                logger.info(f"Vehicle speed: {speed} km/h")

    except can.CanError:
        logger.info("Message NOT sent")

def get_obd_standard(interface):
    '''
    PID 1C
    Get OBD standard this vehicle conforms to
    '''
    bus = can.interface.Bus(bustype='socketcan', channel=interface)

    msg = can.Message(
    arbitration_id=0x7DF,data=[0x02, 0x01, 0x1C], is_extended_id=False
    )

    try:
        bus.send(msg)
        logger.info(f"Message sent on {bus.channel_info}")

        message = bus.recv(10.0)
        if message is None:
            logger.error("Timeout occured, no message.")
        else:
            while message.arbitration_id != 2024:
                message = bus.recv()
                break
            else:
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
                logger.info(f"This vehicle conforms to the {obdstd} standard.")

    except can.CanError:
        logger.warning("Message NOT sent")

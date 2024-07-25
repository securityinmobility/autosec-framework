import sys
sys.path.append("../autosec-framework")

from autosec.core.ressources.bluetooth import BluetoothInterface, BluetoothService, BluetoothDevice, VCard
import autosec.modules.bluetooth.service_discovery as service_discovery
import autosec.modules.bluetooth.rfcomm_scanner as rfcomm_scanner
import autosec.modules.bluetooth.pb_access_service as pb_access_service
import autosec.modules.bluetooth.bluesnarf_service as bluesnarf_service
import autosec.modules.bluetooth.bt_device_imitation_service as bt_device_imitation_service


#define target services
bt_addr = "D8:9B:3B:AB:F5:0E" # change to your device address
interface_name = "Phone" # not really used for anything, but neccessary for networkInterface class
interface = BluetoothInterface(interface_name, bt_addr)
pbap_service = BluetoothService(BluetoothDevice(interface, bt_addr), "RFCOMM", 19)
ftp_service = BluetoothService(BluetoothDevice(interface, bt_addr), "RFCOMM", 7)
opp_service = BluetoothService(BluetoothDevice(interface, bt_addr), "RFCOMM", 12)

# define own interface for imitation
own_iface_name = "hci1"
own_bd_addr = "00:01:95:77:A1:13"
own_interface = BluetoothInterface(own_iface_name, own_bd_addr)

# define Bluetooth device to imitate
imit_bd_addr = "00:23:11:04:F5:8C"
imit_name = "Jlab GO Air"
imit_interface = BluetoothInterface(imit_name, imit_bd_addr)
imit_device = BluetoothDevice(imit_interface, imit_interface.get_network_address(), imit_name)


#------------------------- SERVICE DISCOVERY TEST ---------------------------
print("starting device discovery test")
module_service_discovery = service_discovery.load_module()[0]
assert module_service_discovery.can_run([interface]), "Not enough ressources. (BluetoothInterface)"
service_list = module_service_discovery.run([interface])
if len(service_list) > 0:
    for service in service_list:
        print(f"Name: {service.get_service_name()} \n"
              f"Protocol: {service.get_protocol()} \n"
              f"Port: {service.get_port()} \n"
              f"----------------------------------")
else:
    print("No services found")

#-------------------------- RFCOMM SCANNER TEST -------------------------------
print("starting RFCOMM scanner test")
module_RFCOMM_scanner = rfcomm_scanner.load_module()[0]
assert module_RFCOMM_scanner.can_run([interface]), "Not enough ressources. (BluetoothInterface)"
open_ports_list, closed_ports_list = module_RFCOMM_scanner.run([interface])
if len(open_ports_list) > 0:
    for port in open_ports_list:
        print(f"Port {port.get_port()} is open")
else:
    print("No open RFCOMM ports were found")

if len(closed_ports_list) > 0:
    for port in closed_ports_list:
        print(f"Port {port.get_port()} is closed")
else:
    print("No closed RFCOMM ports were found")

#---------------------------- PHONEBOOK ACCESS TEST --------------------------
print("starting phonebook access test")
module_pb_access_service = pb_access_service.load_module()[0]
assert module_pb_access_service.can_run([pbap_service]), "Not enough ressources. (BluetoothService)"
vcard_list = module_pb_access_service.run([pbap_service])
if len(vcard_list) > 0:
    for vcard in vcard_list:
        print(f"Name: {vcard.get_name()}") # When I use \n after this line the first letter gets replaced by a space
        print(f"Full Name: {vcard.get_full_name()}") # # When I use \n after this line the first letter gets replaced by a space
        print(f"Version: {vcard.get_version()} \n"
              f"Email: {vcard.get_email()} \n"
              f"Tel: {vcard.get_tel()} \n"
              f"Birthday: {vcard.get_birthday()}")
        print("---------------------------------")
else:
    print("No vCards were found")

#------------------------------ BLUESNARFING TEST FTPSERVICE--------------------------
print("starting Bluesnarfing test with FTP Service")
module_bluesnarf_service = bluesnarf_service.load_module()[0]
assert module_bluesnarf_service.can_run([ftp_service]), "Not enough ressources. (BluetoothService)"
file_data_list = module_bluesnarf_service.run([ftp_service])
if len(file_data_list) > 0:
    for file_data in file_data_list:
        print(f"Filename: {file_data.get_filename()} \n"
              f"Data: {file_data.get_data()}")
        print("---------------------------------")
        #file_data.write_to_file(<path>) to test write_to_file method
else:
    print("No files were found")

#------------------------------ BLUESNARFING TEST OPPSERVICE-------------------------------
print("starting Bluesnarfing test with OPP Service")
module_bluesnarf_service = bluesnarf_service.load_module()[0]
assert module_bluesnarf_service.can_run([opp_service]), "Not enough ressources. (BluetoothService)"
file_data_list = module_bluesnarf_service.run([opp_service])
if len(file_data_list) > 0:
    for file_data in file_data_list:
        print(f"Filename: {file_data.get_filename()} \n"
              f"Data: {file_data.get_data()}")
        print("---------------------------------")
        #file_data.write_to_file(<path>) to test write_to_file method
else:
    print("No files were found")

#-------------------------------- DEVICE IMITATION TEST -----------------------------------
print("Starting device imitation test")
module_device_imitation_service = bt_device_imitation_service.load_module()[0]
assert module_device_imitation_service.can_run([imit_device, own_interface, pbap_service]), "Not enough ressources. (BluetoothDevice, BluetoothInterface, BluetoothService)"
imitation_dev = module_device_imitation_service.run([imit_device, own_interface, pbap_service])
input("Press enter to resume...")
print(f"Name: {imitation_dev.get_bd_name()}")
print(f"Address: {imitation_dev.get_bd_addr()}")
print(f"Old Name: {imitation_dev.get_old_name()}")
print(f"Old Address: {imitation_dev.get_old_name()}")
input("Press enter to finish the test...")

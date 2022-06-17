import sys 
sys.path.append("../autosec-framework")

from autosec.core.ressources.can import CanInterface
import autosec.modules.can_scan as can_scan


module = can_scan.load_module()[0]
interface = CanInterface("vcan0")

assert module.can_run([interface]), "Not enough ressources. (CanInterface)"

print("Staring CanScan: ")
devices, data = module.run([interface])
if len(devices) > 0:
    print("Found %s device(s):"%(len(devices)))
    for d in devices:
        print("Interface: %s \tAddress: %s" %(d.get_interface().get_interface_name(), d.get_address()))

    for i in data:
        print("Address: %s \tdata: %s" %(i.get_service(), i.get_data()))
else:
    print("Nothing found")
    

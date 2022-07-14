import sys 
sys.path.append("../autosec-framework")

from autosec.core.ressources.can import CanInterface, IsoTPService
import autosec.modules.obd as ObdServices



module = ObdServices.load_module()[0]
interface = CanInterface("vcan0")
isotp = IsoTPService(interface=interface, src_id=2016, dst_id=2015)  #0x7e0, 0x7df

assert module.can_run([interface, isotp]), "Not enough ressources (CanInterface, IsoTPService)"

print("Starting obd service test:")
obdinfo = module.run([interface, isotp])
if len(obdinfo) > 0:
    for info in obdinfo:
        print("ID: %s \tService: %s \tInfo: %s" %(info.id, info.service, info.info))
else:
    print("Nothing found.")
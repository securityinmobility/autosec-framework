import sys 
sys.path.append("../autosec-framework")

from autosec.core.ressources.can import CanInterface
from autosec.modules.isotp_scan import IsoTpServices





module = IsoTpServices.load_module()[0]
interface = CanInterface("vcan0")

assert module.can_run([interface]), "Not enough ressources (CanInterface)"

print("Start isotp test:")
isotp_list = module.run([interface])

if len(isotp_list) > 0:
    print("Found %s service(s)" %(len(isotp_list)))
    for s in isotp_list:
        print("Interface: %s \tsrc_id: %s \tdst_id: %s " %(s.get_interface().get_interface_name(), s.get_src_id(), s.get_dst_id()))
else:
    print("Nothing found.")
import sys 
sys.path.append("../autosec-framework-master")

from autosec.core.ressources.trc import TRCData
from autosec.core.ressources.can import CanInterface
from autosec.modules import replay_trc



#path = "../headlight-right-idle.trc"
path = "./autosec/test/cantestdata.trc"

module = replay_trc.load_module()[0]
interface = CanInterface("vcan0")
trc = TRCData(path)

assert module.can_run([interface, trc])

print("Starting replaying trc data")
module.run([interface, trc])
print("finished")
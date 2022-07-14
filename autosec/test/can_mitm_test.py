import sys 
sys.path.append("../autosec-framework")

from autosec.core.ressources.can import CanInterface
import autosec.modules.can_bridge as can_bridge


module = can_bridge.load_module()[0]
interface0 = CanInterface("vcan0")
interface1 = CanInterface("vcan1")

assert module.can_run([interface0, interface1]), "Not enough ressources. (CanInterface, CanInterface)"

print("Staring can-mitm: ")
results = module.run([interface0, interface1])
if len(results) > 0:
    for s in results:
        print("Identifier: %s \tData: %s" %(s.service, s.data))
else:
    print("Nothing found.")

print("\nStaring can-mitm with changed data: ")
results = module.run([interface0, interface1], True, 12, 1, b'pwned')
if len(results) > 0:
    for s in results:
        print("Identifier: %s \tData: %s" %(s.service, s.data))
else:
    print("Nothing found.")
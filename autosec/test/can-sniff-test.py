from autosec.core.ressources.can import CanInterface
import autosec.modules.can_scan as can_scan

module = can_scan.load_module()[0]
interface = CanInterface("can1")

assert module.can_run([interface])

print(module.run([interface]))

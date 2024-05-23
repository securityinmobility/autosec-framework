from autosec.core.ressources.ip import InternetInterface, InternetDevice
from autosec.modules.port_scan import PortService

iface = InternetInterface("lo")
device = InternetDevice(iface, "127.0.0.1")
result = PortService().run([iface, device])

print(result)

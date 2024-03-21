import os

from autosec.core.ressources.ip import InternetInterface

from autosec.modules.wlan_p.ocb_join import OcbModeJoin

if os.getuid() != 0:
    print("Script needs to be run with extended privileges")
    exit() 


iface = InternetInterface("wlp9s0")
result = OcbModeJoin(interface=iface)
result = result.run()

print(result)

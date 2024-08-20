from autosec.core.ressources.ip import InternetDevice, InternetInterface
from autosec.modules.ev_charging_station_discovery import EVChargingStationFinder

inet_iface = InternetInterface("eth0", ipv4_address="172.27.106.161", subnet_length=20)
# inet_device = InternetDevice(interface=inet_iface, ipv6="fe80::215:5dff:fe9f:e97b")

results = EVChargingStationFinder().run([inet_iface])
for result in results:
    print(result)

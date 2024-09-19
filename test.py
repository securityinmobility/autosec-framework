from autosec.core.ressources.ip import InternetInterface
from autosec.modules.ev_charging_station_discovery import EVChargingStationFinder

inet_iface = InternetInterface("eth0", ipv4_address="0.0.0.0", subnet_length=20)

results = EVChargingStationFinder().run([inet_iface])

for result in results:
    secc_ip = result.get_device().get_ipv6()
    tcp_port = result.get_port()
    print(f"IP Address of the Charging Station: {secc_ip}")
    print(f"\nTCP Port number of the Charging Station: {tcp_port}\n")
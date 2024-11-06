import nmap
import time

# Assign your modems ip address to the target variable
target = 0
# my_devices are where your device addresses are stored, including your modem
my_devices = []

# Use network_discovery to retrieve the network addresses of your devices and populate the my_devices variable
def network_discovery(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sn')

    for host in nm.all_hosts():
        print(f"Device: {host} is {nm[host].state()}")

def discover_devices(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sn')

    devices = []
    for host in nm.all_hosts():
        devices.append({'ip': host})

    return devices

def continuous_network_monitoring(target, my_devices):
    while True:
        print(f"\nScanning network at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        discovered_devices = discover_devices(target)
        # Compare with known devices and notify you if a new device is found
        imposter = False
        for device in discovered_devices:
            if device['ip'] not in my_devices:
                print(f"New device detected at IP address: {device['ip']}")
                imposter = True
        if not imposter:
            print("No Changes in Network")
        # Update time to your preference
        time.sleep(30)


if __name__ == "__main__":
    continuous_network_monitoring(target, my_devices)

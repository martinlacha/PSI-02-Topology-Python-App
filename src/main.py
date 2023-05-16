from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from pysnmp.hlapi import *

def get_router_ip():
    # vrátí pole
    # [0] - interface
    # [1] 
    print("----------------------------------------")
    gw = conf.route.route('0.0.0.0')
    print(gw)
    print("----------------------------------------")

    router_ip = None
    # Define a DHCP request packet
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
                    BOOTP(chaddr=RandMAC()) / DHCP(options=[("message-type", "discover"), "end"])

    # Send the DHCP request packet and receive the response
    response = srp(dhcp_discover, timeout=5, verbose=False)

    # Process the DHCP response packets
    for index, msg in enumerate(response):
        for packet in response[index]:
            if DHCP in packet and packet[DHCP].options[0][1] == 2:  # DHCP Offer packet
                for option in packet[DHCP].options:
                    if isinstance(option, tuple) and option[0] == 'router':
                        router_ip = option[1]
                        break

    return router_ip

def get_ip():
    router_ip = None

    # Create a DHCP discover packet
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
                    BOOTP(chaddr=RandMAC()) / DHCP(options=[("message-type", "discover"), "end"])

    # Send the DHCP discover packet and receive the response
    response = srp1(dhcp_discover, timeout=5, verbose=False)

    if DHCP in response and response[DHCP].options[0][1] == 2:  # DHCP Offer packet
        router_ip = response[IP].src

    return router_ip

if __name__ == "__main__":
    #print(get_router_ip())
    print(get_ip())

    # Sniff DHCP packets
    #pckt = sniff(iface=conf.iface, filter="udp and (port 67 or port 68)", prn=dhcp_packet_handler, store=0)
    #ip = pckt.getlayer(BOOTP).yiaddr
    #print(ip)
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


def get_router_ip():
    print("----------------------------------------")
    gw = conf.route.route('0.0.0.0')
    print(gw)
    print("----------------------------------------")
    '''
    # Create a DHCP discover packet
    dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(sport=68, dport=67) / BOOTP(chaddr=RandMAC(), xid=RandInt()) / DHCP(options=[('message-type', 'discover'), 'end'])

    # Send the packet and capture the response
    dhcp_offer = srp1(dhcp_discover, timeout=2)

    # Extract the router IP address from the response
    if dhcp_offer:
        router_ip = dhcp_offer[BOOTP].siaddr
        return router_ip
    else:
        return None
    
    '''
    # Create a DHCP request packet
    dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=RandMAC(), xid=RandInt()) / DHCP(options=[("message-type", "request"), ("requested_addr", "0.0.0.0"), "end"])

    # Send the packet and capture the response
    dhcp_offer = srp1(dhcp_request, timeout=10)

    # Extract the router IP address from the response
    print(dhcp_offer)
    if dhcp_offer and 'router' in dhcp_offer[DHCP].options:
        for option in dhcp_offer[DHCP].options:
            if option[0] == 'router':
                router_ip = option[1]
                return router_ip
    return None


if __name__ == "__main__":
    print(get_router_ip())
    print("----------------------------------------")

from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP, dhcp_request
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from pysnmp.hlapi import *

router_ip = None
args = sys.argv
community = "public"

expected_arguments = 2
community_cli_index = 1

def check_cli_args():
    global community
    if len(args) != expected_arguments:
        print(f"Invalid count of CLI arguments Expected: {expected_arguments}, Got: {len(args)}")
        print(f"Usage: python3 main.py <community>")
        exit(1)
    community = args[community_cli_index]
    conf.checkIPaddr = True

def get_router_ip():
    global router_ip
    # vrátí pole
    # [0] - interface
    # [1] - device IP
    # [2] - router IP
    print("----------------------------------------")
    gw = conf.route.route('0.0.0.0')
    router_ip = gw[2]
    print(gw)
    print(f"Router IP: {router_ip}")
    print("----------------------------------------")
    dhcp_response = dhcp_request()

    
    '''
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
    '''
                        

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


def find_topology():
    print("----------------- Topology -----------------")
    routing_table = []
    # SNMP parameters

    # SNMP request to retrieve routing table (OID: 1.3.6.1.2.1.4.21.1)
    var_binds = nextCmd(SnmpEngine(), 
                        CommunityData(community), 
                        UdpTransportTarget((router_ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
                        #ObjectType(ObjectIdentity('1.3.6.1.2.1.4.21.1')),
                        #lexicographicMode=False)

    # Process SNMP response
    for error_indication, error_status, var_bind_table in var_binds:
        print(f"error_indication: {error_indication}")
        if error_indication:
            print(f"Error indicator: {error_indication}")
            return routing_table

        print(f"error_status: {error_status}")
        if error_status:
            print(f"Error status: {error_status.prettyPrint()}")
            return routing_table

        # Extract routing table information
        for var_bind in var_bind_table:
            oid = var_bind[0]
            value = var_bind[1]

            # Process each entry in the routing table
            if str(oid).startswith('1.3.6.1.2.1.4.21.1.7'):  # OID for routing table entry
                index = oid.split('.')[-1]
                route_entry = f"Index: {index}, Next Hop: {value}"
                routing_table.append(route_entry)

    print("--------------------------------------------")
    print(routing_table)
    return routing_table


if __name__ == "__main__":
    check_cli_args()
    get_router_ip()
    find_topology()

    # Sniff DHCP packets
    #pckt = sniff(iface=conf.iface, filter="udp and (port 67 or port 68)", prn=dhcp_packet_handler, store=0)
    #ip = pckt.getlayer(BOOTP).yiaddr
    #print(ip)
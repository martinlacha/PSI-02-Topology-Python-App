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
    conf.checkIPaddr = False

def get_router_ip():
    global router_ip
    # vrátí pole
    # [0] - interface
    # [1] - device IP
    # [2] - router IP
    gw = conf.route.route('0.0.0.0')
    router_ip = gw[2]
    print(gw)
    print(f"Router IP from config: {router_ip}")
    print(f"Send DHCP discover")
    response = dhcp_request()
    response.display()
    
    # Process the DHCP response packets
    dhcp_options = response['DHCP'].options
    for option in dhcp_options:
        if isinstance(option, tuple) and option[0] == 'router':
            router_ip = option[1]
            print(f"Router IP from DHCP discover packet: {router_ip}")
            return
    print(f"Can't found IP address from DHCP dicover packet")


def find_topology():
    print("----------------- Topology -----------------")
    routing_table = []

    # SNMP request to retrieve routing table (OID: 1.3.6.1.2.1.4.21.1)
    var_binds = nextCmd(SnmpEngine(), 
                        CommunityData(community), 
                        UdpTransportTarget((router_ip, 161)),
                        ContextData(),
                        #ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.4.21.1')),
                        lexicographicMode=False)

    # Process SNMP response
    for error_indication, error_status, error_index, var_bind_table in var_binds:
        if error_indication:
            print(f"Error indicator: {error_indication}")
            return routing_table

        if error_status:
            print(f"Error status: {error_status.prettyPrint()}")
            return routing_table

        # Extract routing table information
        for var_bind in var_bind_table:
            oid = var_bind[0]
            value = var_bind[1]

            # Process each entry in the routing table
            if str(oid).startswith('1.3.6.1.2.1.4.21.1.7'):  # OID for routing table entry
                print(f"oid: {str(oid)}")
                index = str(oid).split('.')[-1]
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
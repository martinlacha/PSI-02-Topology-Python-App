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

topology_tree = {}
neighbors_to_process = set()
neighbors_processed = set()

class TopologyEntry:
    def __init__(self, ip, level, children) -> None:
        self._ip = ip
        self._level = level
        self._children = children

    def print_children() -> None:
        print(f"{self._ip} children:")
        for index, child in enumerate(self._children):
            print(f"{index}: {child}")


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
            neighbors_to_process.add(router_ip)
            return
    print(f"Can't found IP address from DHCP dicover packet.")
    print(f"Use IP address from configuration.")
    neighbors_processed.add(router_ip)


def get_routing_table(router_ip):
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
            return None

        if error_status:
            print(f"Error status: {error_status.prettyPrint()}")
            return None

        # Extract routing table information
        for var_bind in var_bind_table:
            oid = var_bind[0]

            # Process each entry in the routing table
            if str(oid).startswith('1.3.6.1.2.1.4.21.1.7'):  # OID for routing table entry
                print(f"oid: {str(oid)}")
                index = str(oid).split('.')[-1]
                route_entry = f"Index: {index}, Value: {var_bind[-1].prettyPrint()}"
                print(route_entry)
                routing_table.append(route_entry)
    return routing_table

'''
def snmp_get(ip):
    # Definujte OID (Object Identifier) pro hodnotu, kterou chcete získat
    oid = ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)

    # Vytvořte SNMP GET operaci
    snmp_get = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(oid)
    )

    # Vykonání SNMP GET operace a získání odpovědi
    error_indication, error_status, error_index, var_binds = next(snmp_get)

    # Zkontrolujte, zda operace byla úspěšná
    if error_indication:
        print(f'Chyba při provedení SNMP operace: {error_indication}')
    elif error_status:
        print(f'SNMP operace vrátila chybu: {error_status.prettyPrint()}')
    else:
        # Získání hodnoty ze získaného vázání proměnných (var_binds)
        for var_bind in var_binds:
            print(f'{var_bind.prettyPrint()}')
'''


def find_topology():
    print("----------------- Finding topology -----------------")
    for ip_to_process in neighbors_to_process:
        print(f"--------- Processing: {ip_to_process} ---------")
        #snmp_get(ip_to_process)
        route_table = get_routing_table(ip_to_process)
        neighbors_processed.remove(ip_to_process)

        # TODO zde projít list routovací tabulky a zkusit získat nějaké info o něm a podle toho přidat do tabulky

        
    print("--------------------------------------------")
    pass


if __name__ == "__main__":
    check_cli_args()
    get_router_ip()
    find_topology()
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
    #response.display()
    
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

# Get routing table from router on IP address 
def get_routing_table(router_ip):
    routing_table = set()

    # SNMP request to retrieve routing table (OID: 1.3.6.1.2.1.4.21.1)
    var_binds = nextCmd(SnmpEngine(), 
                        CommunityData(community), 
                        UdpTransportTarget((router_ip, 161)),
                        ContextData(),
                        #ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.4.21.1')),
                        lexicographicMode=False)

    # Process SNMP response
    print("Routing table:")
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
                route_entry = f"{var_bind[-1].prettyPrint()}"
                routing_table.add(route_entry)
    return routing_table


'''
# Get system ID by IP address
def get_system_id(ip):
    error_indication, error_status, error_index, var_binds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0')))
    )
    if error_indication:
        print(f"Chyba: {error_indication}")
    elif error_status:
        print(f"Chyba: {error_status.prettyPrint()} na indexu {error_index and var_binds[int(error_index) - 1][0] or '?'}")
    else:
        for var_bind in var_binds:
            print(f"System ID: {var_bind.prettyPrint()}")
'''


# Get interfaces IPs
def get_interface_ips(ip):
    error_indication, error_status, error_index, var_binds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('1.3.6.1.2.1.4.20')))
    )

    if error_indication:
        print(f"Error: {error_indication}")
        return
    elif error_status:
        print(f"Error: {error_status.prettyPrint()} at index {error_index and var_binds[int(error_index) - 1][0] or '?'}")
        return

    for var_bind in var_binds:
        print(f"var_bind: {var_bind}")
        for var in var_bind:
            interface_ip = var[1]
            print(f"IP Address: {interface_ip}")


# Get hostname of router by IP address
def snmp_get_hostname(ip):
    error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')))
        )

    if error_indication:
        print(f"Chyba: {error_indication}")
        return None
    elif error_status:
        print(f"Chyba: {error_status.prettyPrint()} na indexu {error_index and var_binds[int(error_index) - 1][0] or '?'}")
        return None
    else:
        for var_bind in var_binds:
            hostname = f"{var_bind[-1].prettyPrint()}"
            print(f"hostname: {hostname}")
            return hostname
    return None

def find_topology():
    print("----------------- Finding topology -----------------")
    while neighbors_to_process:
        ip = neighbors_to_process.pop()
        print(f"Processing: {ip}")

        # Check if ip is router interface
        hostname = snmp_get_hostname(ip)
        if hostname is None:
            print(f"IP {ip} is not valid. Skiping.")
            continue

        #get_system_id(ip)
        get_interface_ips(ip)
        
        #snmp_get(ip_to_process)
        route_table = get_routing_table(ip)
        if ip in route_table:
            route_table.remove(ip)

        
        for route in route_table:
            print(f" - {route}")
            
        #TODO vyfitrovat moje a rekurzivně zavolat znovu
        
        neighbors_processed.add(ip)
        print(f"Processed.")
    print("--------------------------------------------")
    pass


if __name__ == "__main__":
    check_cli_args()
    get_router_ip()
    find_topology()
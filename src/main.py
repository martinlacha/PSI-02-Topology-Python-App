from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP, dhcp_request
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from pysnmp.hlapi import *

# Router IP of node where program starts
router_ip = None
# CLI arguments
args = sys.argv
# Default community name
community = "public"

# Count of expected CLI arguments
expected_arguments = 2
# Index of community string in CLI arguments
community_cli_index = 1
# List of all router hostnames
all_routers = []
# Dictionary of router neighbors
neighbors_dict = {}
# Set of routers that will be process
neighbors_to_process = set()
# Set of router already processed
neighbors_processed = set()

# Check command line arguments
def check_cli_args():
    global community
    if len(args) != expected_arguments:
        print(f"Invalid count of CLI arguments Expected: {expected_arguments}, Got: {len(args)}")
        print(f"Usage: python3 main.py <community>")
        exit(1)
    community = args[community_cli_index]
    conf.checkIPaddr = False


# Get router IP from configuration or from DHCP discover request
def get_router_ip():
    global router_ip
    # [0] - interface, [1] - device IP, [2] - router IP
    gw = conf.route.route('0.0.0.0')
    router_ip = gw[2]
    #print(gw)
    #print(f"Router IP from config: {router_ip}")
    #print(f"Send DHCP discover")
    response = dhcp_request()
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


# Get interfaces IPs
def get_interface_ips(ip):
    index = 1
    router_interfaces = set()
    print(f"Interfaces:")
    for (errorIndication,errorStatus,errorIndex,varBinds) in nextCmd(SnmpEngine(),
        CommunityData(community), UdpTransportTarget((ip, 161)), ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.4.20.1.1')), lexicographicMode=False):
        if errorIndication:
            print(errorIndication, file=sys.stderr)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                                file=sys.stderr)
            break
        else:
            for varBind in varBinds:
                print(f"{index}: {varBind[1].prettyPrint()}")
                router_interfaces.add(varBind[1].prettyPrint())
                index = index + 1
    return router_interfaces


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
        print(f"Error: {error_indication}")
        return None
    elif error_status:
        print(f"Error: {error_status.prettyPrint()} at index {error_index and var_binds[int(error_index) - 1][0] or '?'}")
        return None
    else:
        for var_bind in var_binds:
            hostname = f"{var_bind[-1].prettyPrint()}"
            return hostname
    return None


# Find topology of network and process all found routers
def find_topology():
    print("----------------- Finding topology -----------------")
    while neighbors_to_process:
        ip = neighbors_to_process.pop()
        hostname = snmp_get_hostname(ip)
        if hostname is None:
            print(f"IP {ip} is not valid. Skiping.")
            continue
        if hostname in all_routers:
            #print(f"Router {hostname} was already processed. Skiping")
            continue
        print(f"Processing router {hostname}: {ip}")
        all_routers.append(hostname)
        router_interface_ips = get_interface_ips(ip)
        route_table = get_routing_table(ip)
        if ip in route_table:
            route_table.remove(ip)
        
        for route in route_table:
            route_hostname = snmp_get_hostname(route)
            if route_hostname is None:
                continue
            print(f" - {route_hostname}: {route}")
            if hostname == route_hostname:
                continue
            neighbors_to_process.add(route)
            add_to_neighbors_matrix(hostname, route_hostname)
        neighbors_processed.add(ip)
        print("------------------------------------------------------")


# Add new router neighbor router into matrix
def add_to_neighbors_matrix(router_host_name, neighbor_hostname) -> None:
    global neighbors_dict
    if router_host_name in neighbors_dict:
        neighbors = neighbors_dict[router_host_name]
        neighbors.append(neighbor_hostname)
        neighbors_dict[router_host_name].append(neighbor_hostname)
    else:
        neighbors_dict[str(router_host_name)] = str(neighbor_hostname)


# Print neigbors of every found router
def print_neighbors_matrix() -> None:
    global neighbors_dict
    print(f"Router Neighbors:")
    for router, neighbors in neighbors_dict.items():
        print(f"{router}: {neighbors}")


# Main function
if __name__ == "__main__":
    check_cli_args()
    get_router_ip()
    find_topology()
    print_neighbors_matrix()
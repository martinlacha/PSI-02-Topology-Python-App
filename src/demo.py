from pysnmp.hlapi import *
 
def walk(host, oid):
    for (errorIndication,errorStatus,errorIndex,varBinds) in nextCmd(SnmpEngine(),
        CommunityData('PSIPUB'), UdpTransportTarget((host, 161)), ContextData(),
        ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
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
                print(varBind)
 
#walk('10.0.2.254', '1.3.6.1.2.1.4.24.4.1.1')
walk('192.168.1.2', '1.3.6.1.2.1.4.20.1.1')
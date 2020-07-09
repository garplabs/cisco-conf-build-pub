def hostname(network_device):
    selector = network_device['hostname']
    output = 'hostname {hostname} \n!'.format(hostname=selector)
    return output


def ip_interface(network_device, interface):
    selector = network_device['ip_interfaces'][interface]
    output = 'interface {interface} \n ip address {ip} \n no shutdown \n!'.format(interface=interface,
                                                                                ip=selector['ip_address'])
    return output


def switching_interface_handler(network_device):
    if 'access' in network_device['switching_interfaces']:
        print(switching_interface_access_port(network_device))

    if 'trunk' in network_device['switching_interfaces']:
        print(switching_interface_trunk_port(network_device))

def switching_interface_access_port(network_device):
    access_ports = network_device['switching_interfaces']['access']

    for port in access_ports:

        int_id = port['interface']
        vlan_id = port['vlan_id']
        description = port['description']
        config = 'interface {interface} \n' \
                 ' switchport mode access \n ' \
                 'switchport access vlan {vlan_id} \n ' \
                 'description {description}'.format(interface=int_id,
                                                    vlan_id=vlan_id,
                                                    description=description)
        if 'portfast' in port:
            config = config + '\n spanning-tree portfast'

        print(config)

def switching_interface_trunk_port(network_device):
    trunk_ports = network_device['switching_interfaces']['trunk']

    for port in trunk_ports:
        int_id = port['interface']

        config = 'interface {int_id} \n switchport trunk encap dot1q\n switchport mode trunk'.format(int_id=int_id)

        if 'allowed_vlans' in port:
            allowed_vlans = port['allowed_vlans']
            config = config + '\n switchport trunk allowed vlan {allowed_vlan}'.format(allowed_vlan=allowed_vlans)

        print(config)



def ip_protocols_static_route(network_device,route):
    selector = network_device['ip_protocols']['static'][route]
    output = 'ip route {prefix} {mask} {next_hop} \n!'.format(prefix=selector['prefix'],
                                                          mask=selector['mask'],
                                                          next_hop=selector['next_hop'])

    return output


def ip_protocols_bgp_init(network_device):
    selector = network_device['ip_protocols']['bgp']
    protocol_init = 'router bgp {asn}'.format(asn=selector['asn'])
    output = protocol_init
    return output

def ip_protocols_ospf_init(network_device):
    selector = network_device['ip_protocols']['ospf']
    protocol_init = 'router ospf {process_id}'.format(process_id=selector['process_id'])
    output = protocol_init
    return output

def ip_protocols_ospf_network_statement(statement):

    output = ' network {network} area {area_id}'.format(network=statement['network'],
                                                   area_id=statement['area'])
    return output

def ip_protocols_bgp_neighbor(network_device,neighbor):
    selector = neighbor #network_device['ip_protocols']['bgp']['neighbors']
    output = ' neighbor {neighbor_ip} remote-as {neighbor_as}'.format(neighbor_ip=selector['neighbor_ip'],
                                                                      neighbor_as=selector['neighbor_as'])
    return output


def ip_protocols_bgp_redistribution(redistribute):
    output = ' redistribute {redistribute}'.format(redistribute=redistribute)
    return output


def ip_protocols_bgp_network_statement(network_device,statement):
    selector = network_device['ip_protocols']['bgp']['network_statements'][statement]
    output = ' network {prefix} mask {mask}'.format(prefix=selector['prefix'],
                                                   mask=selector['mask'])
    return output

def ip_protocols_bgp_neighbor_prefix_list(network_device,neighbor,prefix_list):
    selector = network_device['ip_protocols']['bgp']['neighbors'][neighbor]
    neighbor = selector['neighbor_ip']
    direction = prefix_list['list_direction']
    statement = ' neighbor {neighbor_ip} prefix-list '.format(neighbor_ip=neighbor)
    list = prefix_list['list_name'] + ' '
    output = statement + list + direction

    return output


def features_ipsec_pb_tunnel_init(tunnel):
    output = '! \ncrypto isakmp policy {tunnel_number}'.format(tunnel_number=tunnel['tunnel_number'])
    return output

def features_ipsec_pb_phase_1(tunnel):
    selector = tunnel['phase_1']
    encryption = ' encryption {encryption} \n'.format(encryption=selector['encryption'])
    ipsec_hash = ' hash {hash}\n'.format(hash=selector['hash'])
    authentication = ' authentication {authentication}\n'.format(authentication=selector['authentication'])
    group = ' group {group}\n'.format(group=selector['group'])
    key = 'crypto isakmp key {key_number} {key} address {peer_ip}'.format(key=tunnel['pre_shared_key'],
                                                                          peer_ip=tunnel['peer'],
                                                                          key_number=selector['key_number'])

    output = encryption + ipsec_hash + authentication + group + key

    return output

def features_ipsec_pb_phase_2(tunnel):
    selector = tunnel['phase_2']
    transform_set = 'crypto ipsec transform-set {name} {transforms}'.format(name=selector['transform_set']['name'],
                                                                           transforms=" ".join(selector['transform_set']['transforms']))
    output = transform_set

    return output

def features_ipsec_pb_tunnel_crypto_map(tunnel):
    selector = tunnel['phase_2']['crypto_map']
    acl_selector = tunnel['phase_2']['protected_networks']
    map_init = 'crypto map {map_name} {sequence_number} ipsec-isakmp\n'.format(map_name=selector['map_name'],
                                                                               sequence_number=selector['sequence_number'])
    peer = " set peer {peer}\n".format(peer=tunnel['peer'])
    transform = " set transform-set {transform}\n".format(transform=tunnel['phase_2']["transform_set"]['name'])
    match_statement = ' match address {acl_number}'.format(acl_number=acl_selector['acl_number'])

    output = map_init + peer + transform + match_statement

    return output

def features_ipsec_pb_tunnel_acl(tunnel):
    selector = tunnel['phase_2']['protected_networks']
    output = 'access-list {acl_number} permit ip {source_prefix} {source_wildcard} {dest_prefix} {dest_wildcard}'.format(acl_number=selector['acl_number'],
                                                                                                                      source_prefix=selector['source_prefix'],
                                                                                                                      dest_prefix=selector['dest_prefix'],
                                                                                                                      source_wildcard=selector['source_wildcard'],
                                                                                                                      dest_wildcard=selector['dest_wildcard'])
    return output

def features_ipsec_pb_tunnel_route(tunnel):
    selector = tunnel['phase_2']['protected_networks']
    output = 'ip route {dest_prefix} {dest_mask} {peer_ip}'.format(dest_prefix=selector['dest_prefix'],
                                                                   dest_mask=selector['dest_mask'],
                                                                   peer_ip=tunnel['peer'])
    return output

def features_ipsec_pb_tunnel_outbound_int(tunnel):
    crypto_selector = tunnel['phase_2']['crypto_map']
    interface = 'interface {outbound_int}\n'.format(outbound_int=tunnel['phase_2']['outbound_interface'])
    crypto_map = ' crypto map {name}'.format(name=crypto_selector['map_name'])

    output = interface + crypto_map

    return output

def features_route_map(network_device):
    return "yes"

def features_prefix_list(list_entry):
    entry = 'ip prefix-list {name}'.format(name=list_entry['name'])
    sequence_number = ' seq {number} '.format(number=list_entry['sequence_number'])
    action = list_entry['action'] + ' '
    network = list_entry['network']


    if 'operator' in list_entry:
        operator = ' ' + list_entry['operator']
        output = entry + sequence_number + action + network + operator
    else:
        output = entry + sequence_number + action + network

    return output


def constructor(network_device):
    if 'hostname' in network_device:
        print(hostname(network_device))

    if 'ip_interfaces' in network_device:
        for interface in network_device['ip_interfaces']:
            print(ip_interface(network_device,interface))

    if 'switching_interfaces' in network_device:
        print(switching_interface_handler(network_device))

    if 'ip_protocols' in network_device:
        if 'static' in network_device['ip_protocols']:
            for route in network_device['ip_protocols']['static']:
                print(ip_protocols_static_route(network_device,route))
        if 'ospf' in network_device['ip_protocols']:
            print(ip_protocols_ospf_init(network_device))
            if 'network_statements':
                for statement in network_device['ip_protocols']['ospf']['network_statements']:
                    print(ip_protocols_ospf_network_statement(statement))

        if 'bgp' in network_device['ip_protocols']:
            print(ip_protocols_bgp_init(network_device))
            if 'neighbors' in network_device['ip_protocols']['bgp']:
                for neighbor in network_device['ip_protocols']['bgp']['neighbors']:
                    print(ip_protocols_bgp_neighbor(network_device,neighbor))
                    if 'prefix_lists' in neighbor:
                        # print(ip_protocols_bgp_neighbor_prefix_list(network_device,neighbor))
                        for prefix_list in network_device['ip_protocols']['bgp']['neighbors'][neighbor]['prefix_lists']:
                            print(ip_protocols_bgp_neighbor_prefix_list(network_device,neighbor,prefix_list))

            if 'redistribution' in network_device['ip_protocols']['bgp']:
                for statement in network_device['ip_protocols']['bgp']['redistribution']:
                    print(ip_protocols_bgp_redistribution(statement))
            if 'network_statements' in network_device['ip_protocols']['bgp']:
                for statement in network_device['ip_protocols']['bgp']['network_statements']:
                    print(ip_protocols_bgp_network_statement(network_device,statement))

    if 'features' in network_device:
        if 'ipsec_policy_based' in network_device['features']:
            for tunnel in network_device['features']['ipsec_policy_based']:
                print(features_ipsec_pb_tunnel_init(tunnel))
                if 'phase_1':
                    print(features_ipsec_pb_phase_1(tunnel))
                if 'phase_2':
                    print(features_ipsec_pb_phase_2(tunnel))
                    if 'crypto_map':
                        print(features_ipsec_pb_tunnel_crypto_map(tunnel))

                if 'protected_networks':
                    print(features_ipsec_pb_tunnel_acl(tunnel))
                print(features_ipsec_pb_tunnel_route(tunnel))
                print(features_ipsec_pb_tunnel_outbound_int(tunnel))
        if 'prefix_list' in network_device['features']:
            for entry in network_device['features']['prefix_list']:
                print(features_prefix_list(entry))

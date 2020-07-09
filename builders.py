import configurations


def build_hostname(network_device):
    if 'hostname' in network_device:
        return configurations.hostname(network_device)


def build_interfaces(network_device):
    section = []
    if 'ip_interfaces' in network_device:
        section.append(configurations.ip_interface_handler(network_device))

    if 'switching_interfaces' in network_device:
       section.append(configurations.switching_interface_handler(network_device))

    return '\n'.join(section)


def build_ip_protocols(network_device):
    section = []
    if 'ip_protocols' in network_device:
        if 'static' in network_device['ip_protocols']:
             section.append(configurations.static_route_handler(network_device))
        if 'ospf' in network_device['ip_protocols']:
            section.append(configurations.ospf_handler(network_device))
        if 'bgp' in network_device['ip_protocols']:
            section.append(configurations.bgp_handler(network_device))

        return '\n'.join(section)


def build_features(network_device):
    section = []
    if 'features' in network_device:
        if 'ipsec_policy_based' in network_device['features']:
            for tunnel in network_device['features']['ipsec_policy_based']:
                section.append(configurations.features_ipsec_pb_tunnel_init(tunnel))
                if 'phase_1':
                    section.append(configurations.features_ipsec_pb_phase_1(tunnel))
                if 'phase_2':
                    section.append(configurations.features_ipsec_pb_phase_2(tunnel))
                    if 'crypto_map':
                        section.append(configurations.features_ipsec_pb_tunnel_crypto_map(tunnel))

                if 'protected_networks':
                    section.append(configurations.features_ipsec_pb_tunnel_acl(tunnel))
                section.append(configurations.features_ipsec_pb_tunnel_route(tunnel))
                section.append(configurations.features_ipsec_pb_tunnel_outbound_int(tunnel))

    return '\n'.join(section)


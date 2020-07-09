import builders


def config_array_build(network_device):
    config = [builders.build_hostname(network_device),
              builders.build_interfaces(network_device),
              builders.build_ip_protocols(network_device),
              builders.build_features(network_device),
              ]

    return config


def config_term_output(network_device):
    config = config_array_build(network_device)
    for line in config:
        print(line)
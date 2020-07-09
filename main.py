import yaml
import generators

target = 'CE-RTR-8-test-bgp-dict-1.yaml'

with open(target) as file:
    config = yaml.full_load(file)
    generators.config_term_output(config)

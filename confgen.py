import yaml
import generators
from docopt import docopt

#target = 'CE-RTR-8-test-bgp-dict-1.yaml'

usage = """
Usage: main <file_name>

Arguments:
  file_name                   file to run config on 

"""


args = docopt(usage)

target = args['<file_name>']

with open(target) as file:
    config = yaml.full_load(file)
    generators.config_term_output(config)

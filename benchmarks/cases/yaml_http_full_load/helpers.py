import yaml


def parse_config(text):
    return yaml.full_load(text)

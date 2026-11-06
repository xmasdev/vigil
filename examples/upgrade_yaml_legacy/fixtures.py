"""Loads test fixtures written years ago."""
import yaml


def load_fixture(path):
    with open(path) as fh:
        return yaml.load(fh)


def load_all(path):
    with open(path) as fh:
        return list(yaml.load_all(fh, yaml.FullLoader))


def save_fixture(path, data):
    with open(path, "w") as fh:
        yaml.dump(data, fh, default_flow_style=False)

from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).parent / "config.yaml"


def load_settings():
    with open(CONFIG_PATH) as fh:
        return yaml.full_load(fh)

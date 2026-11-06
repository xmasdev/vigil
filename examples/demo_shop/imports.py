import yaml


def import_catalog(text):
    data = yaml.load(text, Loader=yaml.FullLoader)
    return data.get("products", [])

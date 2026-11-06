import yaml


class RecipeImporter:
    def __init__(self):
        self.loader = yaml.FullLoader

    def parse(self, raw):
        return yaml.load(raw, Loader=self.loader)

from flask import Flask, request

from importer import RecipeImporter

app = Flask(__name__)
importer = RecipeImporter()


@app.route("/recipes/import", methods=["POST"])
def import_recipe():
    uploaded = request.files["recipe"]
    recipe = importer.parse(uploaded.read())
    return {"title": recipe["title"]}

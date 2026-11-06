from flask import Flask, request
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)
env = SandboxedEnvironment()


@app.post("/preview")
def preview_email_template():
    """Let customers preview their own notification templates."""
    template = env.from_string(request.form["template"])
    return template.render(customer={"name": "Ada"})

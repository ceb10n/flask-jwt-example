from flask import Flask

app = Flask(__name__)


@app.route('/auth/users', methods=['POST'])
def register():
    pass


@app.route('/auth/login', methods=['POST'])
def register():
    pass


app.run()

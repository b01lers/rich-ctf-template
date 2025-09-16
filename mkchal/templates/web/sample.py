from flask import Flask
# Sample web flask challenge which serves the flag feel free to delete this

app = Flask(__name__)

@app.route("/")
def index():
    with open("./flag.txt", "r") as f:
        file = f.read()
    return "Hello I am challenge: {name} and my flag is " + file

if __name__ == "__main__":
    app.run("0.0.0.0", {port})
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.get("/")
def get_status():
    return jsonify({"status": "up"})

@app.post("/")
def post_status():
    if "payload" in request.json:
        print(request.json["payload"])
        return jsonify({"payload": request.json["payload"]})
    else:
        return jsonify({"status": "up"})

from flask import Flask, request, jsonify
import socket
from os import environ
from threading import Thread

BUFFER_SIZE = int(environ.get("MOCK_UDP_BUFFER_SIZE", "65536"))

def run_udp_server(sock: socket.socket, buf_size: int = BUFFER_SIZE):
    while True:
        data, addr = sock.recvfrom(buf_size)
        print("Message from (%s): %s" % (addr, data))
        sock.sendto(data, addr)

def udp_server(sock: socket.socket, host: str = "0.0.0.0", port: int = 6000) -> Thread:
    sock.bind((host, port))
    print(f"UDP server has been started listening on '{host}:{port}'")
    thread = Thread(target=run_udp_server, args=(sock,))
    thread.start()
    return thread

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


if __name__ == "__main__":
    thread = udp_server(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    app.run(port=environ.get("LOCAL_PORT", "5000"))
    thread.join()

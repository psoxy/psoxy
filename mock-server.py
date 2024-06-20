#!/bin/python3

import socket

HOST = '127.0.0.1' 
PORT = 2152

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        with conn:
            while True:
                if not conn:
                    break
                data = conn.recv(1024)
                if not data:
                    break
                print(conn, data)

#!/bin/python3
# -*- coding: utf-8 -*-

# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, active_count
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
from optparse import OptionParser
from aes import AESCipher

parser = OptionParser()
parser.add_option("-c", "--use-external-config",
                  action="store_true", dest="use_external_config", default=False,
                  help="uses the external configs in './config.py'")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="be more verbose")
parser.add_option("-p", "--port",
                  action="store", dest="port", default=None,
                  help="set the port")

(options, args) = parser.parse_args()

if options.use_external_config:
    from config import *
else:
    #
    # Configuration
    #
    MAX_THREADS = 200
    BUFSIZE = 16384
    SEND_CHUNK_SIZE = 1024
    TIMEOUT_SOCKET = 5
    LOCAL_ADDR = '0.0.0.0'
    LOCAL_PORT = 2152
    LOCAL_UUID='19237dd2-65a9-4783-9ca6-6202dfffe4b5'
    OUTGOING_INTERFACE = ""
    # GTP HEADER TEMPLATE
    GTP_HEADER_FLAGS=48
    GTP_HEADER_TYPE=255
    GTP_HEADER_ID=b"\x00\x00\x79\x32"
    # SERVER OK
    SERVER_OK=b'OK'

PRINT_PREFIX=""

if options.port is not None:
    LOCAL_PORT = int(options.port)
    PRINT_PREFIX = f"[{LOCAL_PORT}]"

class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        try:
            print(PRINT_PREFIX, "{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
        except TypeError:
            print(PRINT_PREFIX, f"{msg} - {err}")
    else:
        traceback.print_exc()

def proxy_loop(socket_src, socket_dst, teid: int, aes_client):
    """ Wait for network activity """
    prev_size_segment = b''
    is_recving = False
    is_recving_size = 0
    is_recving_buffer = b''
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                if sock is socket_dst:
                    data = sock.recv(BUFSIZE)
                    if not data:
                        return
                    data_packet = aes_client.encrypt(data)
                    size_packet = aes_client.encrypt(pack('!4s', len(data_packet).to_bytes(4, sys.byteorder)))
                    if options.verbose:
                        print(PRINT_PREFIX, len(data), "->", len(size_packet),  len(data_packet))
                    socket_src.send(size_packet)
                    socket_src.send(data_packet)
                    # TODO: Should create a very big packet and encrypt it (with padding)
                    #       and send it with the length at the begining 4 bytes and then send
                    #       the rest so that the client know what to expect and can wait until
                    #       it receives full block
                    # for i in range(0, len(data), SEND_CHUNK_SIZE):
                    #     payload = data[i:i+SEND_CHUNK_SIZE]
                    #     socket_src.send(aes_client.encrypt(payload))
                        # sleep(0.001)
                else:
                    if is_recving:
                        data = sock.recv(SEND_CHUNK_SIZE)
                        if not data:
                            return
                        is_recving_buffer = is_recving_buffer + data
                        if options.verbose:
                            print(PRINT_PREFIX, "Received:", len(data))
                        while is_recving_size <= len(is_recving_buffer):
                            if options.verbose:
                                print(PRINT_PREFIX, "Received Size:", is_recving_size)
                            data = is_recving_buffer[:is_recving_size]
                            payload = aes_client.decrypt(data)
                            socket_dst.send(payload)
                            if len(is_recving_buffer) > is_recving_size:
                                is_recving_buffer = is_recving_buffer[is_recving_size:]
                                if len(is_recving_buffer) >= 44:
                                    payload = aes_client.decrypt(is_recving_buffer[:44])
                                    is_recving = True
                                    is_recving_size = int.from_bytes(payload, sys.byteorder)
                                    is_recving_buffer = is_recving_buffer[44:]
                                    prev_size_segment = b''
                                    if options.verbose:
                                        print(PRINT_PREFIX, "Going to continue receive with size:", is_recving_size)
                                else:
                                    if options.verbose:
                                        print(PRINT_PREFIX, "Found partial size with size:", len(is_recving_buffer), "and context:", is_recving_buffer)
                                    prev_size_segment = is_recving_buffer
                                    is_recving_buffer = b''
                                    is_recving = False
                                    break
                            else:
                                is_recving_buffer = b''
                                is_recving = False
                    else:
                        data = prev_size_segment + sock.recv(44 - len(prev_size_segment))
                        if len(prev_size_segment):
                            if options.verbose:
                                print(PRINT_PREFIX, "Resuming partial with size:", len(data), "and context:", data)
                        if not data:
                            return
                        payload = aes_client.decrypt(data)
                        is_recving = True
                        is_recving_size = int.from_bytes(payload, sys.byteorder)
                        is_recving_buffer = b''
                        prev_size_segment = b''
                        if options.verbose:
                            print(PRINT_PREFIX, "Going to receive with size:", is_recving_size)
                        # socket_dst.send(payload)
        except socket.error as err:
            error("Loop failed", err)
            return

def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print(PRINT_PREFIX, "Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0

def request_client(wrapper, aes_client):
    """ Client request details """
    # +-----+----+-----+----------+----------+------+----------+----------+
    # | GTP | ID | LEN | DST.PORT | SRC.PORT | ATYP | DST.ADDR | SRC.ADDR |
    # +-----+----+-----+----------+----------+------+----------+----------+
    try:
        gtp_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False

    gtp_header_flags, gtp_header_type = unpack("!BB", gtp_request[:2])
    
    # Check VER, CMD and RSV
    if (
            gtp_header_flags != GTP_HEADER_FLAGS or
            gtp_header_type != GTP_HEADER_TYPE
    ):
        return False
    

    teid = unpack("!4s", gtp_request[4:8])[0]

    decrypted_gtp_request = aes_client.decrypt(gtp_request[8:])
    
    _, _, dst_port, _, atype = unpack("!HHHHB", decrypted_gtp_request[:9])
    atype = int(atype)

    # IPV4
    if atype == 0:
        dst_addr = socket.inet_ntoa(decrypted_gtp_request[9:13])
    # DOMAIN NAME
    elif atype == 1:
        dst_addr_size = unpack('>H', decrypted_gtp_request[9:11])[0]
        dst_addr = decrypted_gtp_request[11: 11 + dst_addr_size]
    else:
        return False
    
    ack_payload = aes_client.encrypt(SERVER_OK)
    wrapper.send(pack("!BBH4s",
            GTP_HEADER_FLAGS,
            GTP_HEADER_TYPE,
            len(ack_payload),
            teid
    ) + ack_payload)

    print(PRINT_PREFIX, dst_addr, dst_port)
    return (dst_addr, dst_port, teid)

def request(wrapper):
    aes_client = AESCipher(SEND_CHUNK_SIZE, LOCAL_UUID)
    dst = request_client(wrapper, aes_client)
    if dst:
        # socket_dst = connect_to_dst(dst[0], dst[1])
        teid = dst[2]
        dst = dst[:2]
        socket_dst = connect_to_dst(dst[0], dst[1])
    # start proxy
    if dst and socket_dst != 0:
        # TODO: add AES encryption and decryption during data transfer to all modules
        proxy_loop(wrapper, socket_dst, teid, aes_client)
    if wrapper != 0:
        wrapper.close()
    if dst and socket_dst != 0:
        socket_dst.close()

def connection(wrapper):
    """ Function run by a thread """
    request(wrapper)

def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock

def create_socket_udp() -> socket:
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock

def bind_port(sock: socket):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        print(PRINT_PREFIX, 'Bind {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(0)
    return sock

def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print(PRINT_PREFIX, 'Signal handler called with signal', signum)
    EXIT.set_status(True)

def main():
    """ Main function """
    print(PRINT_PREFIX, "Starting server")
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    while not EXIT.get_status():
        if active_count() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)
        recv_thread = Thread(target=connection, args=(wrapper, ))
        recv_thread.start()
    new_socket.close()

EXIT = ExitStatus()
if __name__ == '__main__':
    main()








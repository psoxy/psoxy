#!/bin/python3
# -*- coding: utf-8 -*-
"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

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
import random
import string
from optparse import OptionParser
from aes import AESCipher
from psoxysocket import PsoxySocket

parser = OptionParser()
parser.add_option("-c", "--use-external-config",
                  action="store_true", dest="use_external_config", default=False,
                  help="use the external configs in './config.py'")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="be more verbose")
parser.add_option("--local-host", action="store", dest="local_host", default="0.0.0.0")
parser.add_option("--local-port", action="store", dest="local_port", default="25663")
parser.add_option("--remote-host", action="store", dest="remote_host", default="127.0.0.1")
parser.add_option("--remote-port", action="store", dest="remote_port", default="2153")
parser.add_option("--remote-uuid", action="store", dest="remote_uuid", default='b050bc40-d8be-45df-aabc-60e0515d935a')


(options, args) = parser.parse_args()

if options.use_external_config:
    from config import *
else:
    #
    # Configuration
    #
    MAX_THREADS = 200
    BUFSIZE = 16384
    SEND_UDP_CHUNK_SIZE = 65536
    SEND_CHUNK_SIZE = 16384
    TIMEOUT_SOCKET = 5
    LOCAL_ADDR = options.local_host
    LOCAL_PORT = int(options.local_port)
    # Parameter to bind a socket to a device, using SO_BINDTODEVICE
    # Only root can set this option
    # If the name is an empty string or None, the interface is chosen when
    # a routing decision is made
    # OUTGOING_INTERFACE = "wlo1"
    OUTGOING_INTERFACE = ""
    #
    # Constants
    #
    '''Version of the protocol'''
    # PROTOCOL VERSION 5
    VER = b'\x05'
    '''Method constants'''
    # '00' NO AUTHENTICATION REQUIRED
    M_NOAUTH = b'\x00'
    # 'FF' NO ACCEPTABLE METHODS
    M_NOTAVAILABLE = b'\xff'
    '''Command constants'''
    # CONNECT '01'
    CMD_CONNECT = b'\x01'
    # BIND '03'
    CMD_BIND = b'\x03'
    '''Address type constants'''
    # IP V4 address '01'
    ATYP_IPV4 = b'\x01'
    # DOMAINNAME '03'
    ATYP_DOMAINNAME = b'\x03'
    # GTP HEADER TEMPLATE
    GTP_HEADER_FLAGS=48
    GTP_HEADER_TYPE=255
    GTP_HEADER_ID=b"\x00\x00\x79\x32"
    # RANDOM PACKET
    RANDOM_PACKET_LEN_RANGE=(256,1024)
    # SERVER
    SERVER_OK=b'OK'
    SERVER_ADDR=options.remote_host
    SERVER_PORT=int(options.remote_port)
    SERVER_UUID=options.remote_uuid
    SERVERS = [
        (SERVER_ADDR, SERVER_PORT, SERVER_UUID),
    ]

NUM_SERVERS = len(SERVERS)
TCP_TRANSPORT = b'\x00'
UDP_TRANSPORT = b'\x01'
known_transports = [
    TCP_TRANSPORT,
    UDP_TRANSPORT,
]

def random_server():
    return SERVERS[random.randrange(NUM_SERVERS)]

def random_packet() -> str:
    N = random.randint(*RANDOM_PACKET_LEN_RANGE)
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

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
            print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
        except TypeError:
            print(f"{msg} - {err}")
    else:
        traceback.print_exc()


def proxy_loop(socket_src: PsoxySocket, socket_dst: PsoxySocket, teid: int, aes_server):
    """ Wait for network activity """
    prev_size_segment = b''
    is_recving = False
    is_recving_size = 0
    is_recving_buffer = b''
    _socket_side_udp_src = socket_src.get_side_udp_socket()
    _socket_src = socket_src.get_socket()
    _socket_dst = socket_dst.get_socket()
    sockets = {
        _socket_side_udp_src: socket_src,
        _socket_src: socket_src,
        _socket_dst: socket_dst,
    }
    while not EXIT.get_status():
        try:
            if _socket_side_udp_src is not None:
                reader, _, _ = select.select([_socket_side_udp_src, _socket_src, _socket_dst], [], [], 1)
            else:
                reader, _, _ = select.select([_socket_src, _socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            # reader = list(map(lambda sock: sockets[sock], reader))
            for _sock in reader:
                sock = sockets[_sock]
                if _sock is _socket_dst:
                    if options.verbose: 
                        print("Receiving")
                    if is_recving:
                        if _socket_side_udp_src is not None:
                            data = sock.recv(SEND_UDP_CHUNK_SIZE)
                        else:
                            data = sock.recv(SEND_CHUNK_SIZE)
                        if not data:
                            return
                        is_recving_buffer = is_recving_buffer + data
                        if options.verbose: 
                            print("Received:", len(data))
                        while is_recving_size <= len(is_recving_buffer):
                            if options.verbose: 
                                print("Received Size:", is_recving_size)
                            data = is_recving_buffer[:is_recving_size]
                            payload = aes_server.decrypt(data)
                            socket_src.send(payload)
                            if len(is_recving_buffer) > is_recving_size:
                                is_recving_buffer = is_recving_buffer[is_recving_size:]
                                if len(is_recving_buffer) >= 44:
                                    payload = aes_server.decrypt(is_recving_buffer[:44])
                                    is_recving = True
                                    is_recving_size = int.from_bytes(payload, sys.byteorder)
                                    is_recving_buffer = is_recving_buffer[44:]
                                    prev_size_segment = b''
                                    if options.verbose: 
                                        print("Going to continue receive with size:", is_recving_size)
                                else:
                                    if options.verbose: 
                                        print("Found partial size with size:", len(is_recving_buffer))
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
                                print("Resuming partial with size:", len(data), "and context:", data)
                        if not data:
                            return
                        payload = aes_server.decrypt(data)
                        is_recving = True
                        is_recving_size = int.from_bytes(payload, sys.byteorder)
                        is_recving_buffer = b''
                        prev_size_segment = b''
                        if options.verbose: 
                            print("Going to receive with size:", is_recving_size)
                elif _sock is _socket_side_udp_src or _sock is _socket_src:
                    if _socket_side_udp_src is not None:
                        data = sock.recv(SEND_UDP_CHUNK_SIZE)
                    else:
                        data = sock.recv(SEND_CHUNK_SIZE)
                    if not data:
                        return
                    data_packet = aes_server.encrypt(data)
                    size_packet = aes_server.encrypt(pack('!4s', len(data_packet).to_bytes(4, sys.byteorder)))
                    if options.verbose: 
                        print(len(data), "->", len(size_packet),  len(data_packet))
                    socket_dst.send(size_packet)
                    socket_dst.send(data_packet)
                else:
                    data = sock.recv(SEND_CHUNK_SIZE)
                    if not data:
                        return
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock, teid = create_socket(socket.SOCK_STREAM)
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print("Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
    try:
        print(dst_addr, dst_port)
        sock.connect((dst_addr, dst_port))
        return sock, teid
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0, teid


def request_client(wrapper):
    """ Client request details """
    # +-----+-----+-------+------+----------+----------+
    # | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +-----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    # Check VER, CMD and RSV
    _VER, _CMD, _RSV = s5_request[0:1], s5_request[1:2], s5_request[2:3]
    if (
        _VER != VER or
        (_CMD != CMD_CONNECT and _CMD != CMD_BIND) or
        _RSV != b'\x00'
    ):
        return False
    dst_trans = 0
    if _CMD == CMD_BIND:
        dst_trans = 1

    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        dst_type = 0
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        dst_type = 1
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    else:
        return False
    if isinstance(dst_addr, str):
        print(f"{'udp' if dst_trans else 'tcp'}://{dst_addr}:{dst_port}")
    else:
        print(f"{'udp' if dst_trans else 'tcp'}://{dst_addr.decode()}:{dst_port}")
    return (dst_type, dst_addr, dst_port, dst_trans)

def request(wrapper: PsoxySocket):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    dst = request_client(wrapper)
    # Server Reply
    # +-----+-----+-------+------+----------+----------+
    # | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +-----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
    if dst:
        # socket_dst = connect_to_dst(dst[0], dst[1])
        selected_server = random_server()
        socket_dst, teid = connect_to_dst(selected_server[0], selected_server[1])
    if not dst or socket_dst == 0:
        rep = b'\x01'
    else:
        rep = b'\x00'
        if dst[3]:
            wrapper.add_side_udp_socket()
            wrapper.bind(("", 0))
            src_bind_spec = wrapper.getsockname()
            print(src_bind_spec)
            bnd = socket.inet_aton(src_bind_spec[0])
            bnd += pack(">H", src_bind_spec[1])
        else:
            bnd = socket.inet_aton(socket_dst.getsockname()[0])
            bnd += pack(">H", socket_dst.getsockname()[1])


    # Connect to server
    if rep == b'\x00':
        _random_packet = random_packet().encode()
        aes_server = AESCipher(SEND_CHUNK_SIZE, selected_server[2])
        if dst[0] == 0: # IPv4
            header = pack("!HHHHBB4s4s",
                0,
                len(_random_packet),
                0 if dst[3] else dst[2],
                0,
                int.from_bytes(known_transports[dst[3]], sys.byteorder),
                0,
                socket.inet_aton(dst[1]),
                socket.inet_aton("0.0.0.0")
            )
        else: # Host Name
            header = pack("!HHHHBBH",
                0,
                len(_random_packet),
                0 if dst[3] else dst[2],
                0,
                int.from_bytes(known_transports[dst[3]], sys.byteorder),
                1,
                len(dst[1])
            ) + dst[1] + pack("!4s",
                socket.inet_aton("0.0.0.0")
            )
        packet = aes_server.encrypt(header + _random_packet)
        socket_dst.send(pack("!BBH4s",
                GTP_HEADER_FLAGS,
                GTP_HEADER_TYPE,
                len(packet),
                teid.to_bytes(4, sys.byteorder)
        ) + packet)
        data = socket_dst.recv(BUFSIZE)
        if len(data) > 8:
            if aes_server.decrypt(data[8:]) != SERVER_OK:
                rep = b'\x01'
        else:
            rep = b'\x01'
    
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd

    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':
        # wrapper_udp = create_udp_for_tcp(wrapper)
        proxy_loop(wrapper, socket_dst, teid, aes_server)
    if wrapper != 0:
        wrapper.close()
    if dst and socket_dst != 0:
        # _random_packet = random_packet().encode()
        # packet = GTP_HEADER_FLAGS + GTP_HEADER_TYPE + pack(">H", len(_random_packet)+12) + pack(">4s", teid.to_bytes(4, sys.byteorder)) + pack(">H", 0) + pack(">H", 0) + pack(">4s", socket.inet_aton("0.0.0.0")) + pack(">4s", socket.inet_aton("0.0.0.0")) + _random_packet
        # socket_dst.send(packet)
        socket_dst.close()


def subnegotiation_client(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    for method in methods:
        if method == ord(M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def subnegotiation(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message
    """
    method = subnegotiation_client(wrapper)
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False
    return True


def connection(wrapper):
    """ Function run by a thread """
    if subnegotiation(wrapper):
        request(wrapper)


def create_socket(custom_socket_type = None):
    """ Create an INET, STREAMing socket """
    try:
        
        if custom_socket_type is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = PsoxySocket(custom_socket_type)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock, random.randint(1,2**32)

def create_socket_udp():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock, random.randint(1,2**32)


def bind_port(sock):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        print('Bind {}'.format(str(LOCAL_PORT)))
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
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)
    exit(signum)


def main():
    """ Main function """
    print("Starting client")
    new_socket, _ = create_socket(socket.SOCK_STREAM)
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    while not EXIT.get_status():
        if active_count() > MAX_THREADS:
            print("too much connection")
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
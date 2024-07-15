import socket
from struct import pack, unpack

class PsoxySocket():
    def __init__(self, type = socket.SOCK_STREAM, family = socket.AF_INET, new_socket: socket.socket | None = None):
        self.family = family
        self.type = type
        if new_socket is not None:
            self.socket = new_socket
        else:
            self.socket = socket.socket(family, self.type)
        self.side_udp_socket = None
        self.addr = ['', 0]
        self.udp_diagram_socks_header = b""
    
    def listen(self, backlog: int):
        return self.socket.listen(backlog)
    
    def bind(self, addr: tuple[str, int]):
        if self.side_udp_socket is not None:
            return self.side_udp_socket.bind(addr)
        else:
            return self.socket.bind(addr)
    
    def accept(self):
        new_socket, dest_addr =  self.socket.accept()
        new_psoxy_socket = PsoxySocket(self.type, self.family, new_socket)
        new_psoxy_socket.addr = dest_addr
        return new_psoxy_socket, dest_addr
    
    def setblocking(self, flag):
        self.socket.setblocking(flag)

    def connect(self, addr: tuple[str, int]):
        if self.type == socket.SOCK_DGRAM:
            return None
        else:
            return self.socket.connect(addr)
    
    def add_side_udp_socket(self):
        self.side_udp_socket = socket.socket(self.family, socket.SOCK_DGRAM)
    
    def settimeout(self, value: float | None):
        return self.socket.settimeout(value)
    
    def setsockopt(self, level: int, optname: int, value):
        return self.socket.setsockopt(level, optname, value)
    
    def recv(self, bufsize: int):
        if self.side_udp_socket is not None:
            data, self.addr = self.side_udp_socket.recvfrom(bufsize)
            self.udp_diagram_socks_header = self.copy_socks_address_from_udp(data)
            return data
        if self.type == socket.SOCK_DGRAM:
            data, _ = self.socket.recvfrom(bufsize)
            return data
        return self.socket.recv(bufsize)
    
    def send(self, data):
        if self.side_udp_socket is not None:
            return self.side_udp_socket.sendto(self.udp_diagram_socks_header + data, self.addr)
        if self.type == socket.SOCK_DGRAM:
            ret = self.extract_address_from_udp(data)
            if ret is not None:
                data, addr = ret
                return self.socket.sendto(data, addr)
            else:
                raise ValueError("Unable to find the address in the data")
        return self.socket.send(data)

    def sendall(self, data):
        return self.socket.sendall(data)
    
    def getsockname(self):
        if self.side_udp_socket is not None:
            return self.side_udp_socket.getsockname()
        else:
            return self.socket.getsockname()
    
    def close(self):
        if self.side_udp_socket is not None:
            return self.side_udp_socket.close(), self.socket.close()
        return self.socket.close()
    
    def __bool__(self):
        return self.socket.__bool__()
    
    def __eq__(self, value: object) -> bool:
        return self.socket == value
    
    def __ne__(self, value: object) -> bool:
        return self.socket != value
    
    def get_socket(self):
        return self.socket
    
    def get_side_udp_socket(self):
        return self.side_udp_socket
    
    def copy_socks_address_from_udp(self, data: bytes) -> bytes | None:
        RSV, FRAG, ATYP = unpack("!HBB", data[:4])

        if RSV != 0 or FRAG != 0:
            return None

        # IPV4
        if ATYP == 1:
            size = 10
        # DOMAIN NAME
        elif ATYP == 3:
            sz_domain_name = data[4]
            size = 7 + sz_domain_name
        else:
            return None
        return data[:size]
    
    def extract_address_from_udp(self, data: bytes) -> tuple[bytes, tuple[str, int]] | None:
        RSV, FRAG, ATYP = unpack("!HBB", data[:4])

        if RSV != 0 or FRAG != 0:
            return None

        # IPV4
        if ATYP == 1:
            dst_addr = socket.inet_ntoa(data[4:8])
            dst_port = unpack('>H', data[8:10])[0]
            size = 10
        # DOMAIN NAME
        elif ATYP == 3:
            sz_domain_name = data[4]
            dst_name = data[5: 5 + sz_domain_name].decode()
            port_to_unpack = data[5 + sz_domain_name:5 + sz_domain_name + 2]
            dst_port = unpack('>H', port_to_unpack)[0]
            dst_addr = socket.gethostbyname(dst_name)
            size = 7 + sz_domain_name
        else:
            return None

        return data[size:], (dst_addr, dst_port)

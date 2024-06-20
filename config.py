#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 16384
SEND_CHUNK_SIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = "0.0.0.0"
LOCAL_PORT = 1563
LOCAL_UUID = ""
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
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'

# GTP HEADER TEMPLATE
GTP_HEADER_FLAGS = 48
GTP_HEADER_TYPE = 255
GTP_HEADER_ID = b"\x00\x00\x79\x32"
# RANDOM PACKET
RANDOM_PACKET_LEN_RANGE = (256,1024)
# SERVER
SERVER_OK = b'OK'
SERVER_ADDR = "172.93.144.163"
SERVER_PORT = 443
SERVER_UUID = "19237dd2-65a9-4783-9ca6-6202dfffe4b5"
SERVERS = []
for i in range(1):
    SERVERS.append(("172.93.144.163", 443 + i, '19237dd2-65a9-4783-9ca6-6202dfffe4b5'))
# MOCK
SMALL_SIZE=256
MEDIUM_SIZE=1024
LARGE_SIZE=8192
MOCK_SERVER_ADDR = "172.23.0.6"
MOCK_SERVER_PORT = 5000
TEST = "medium"
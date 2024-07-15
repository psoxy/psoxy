import socket, socks, requests, random, string, base64, time
from optparse import OptionParser
from os import environ
import socket

parser = OptionParser()
parser.add_option("-c", "--use-external-config",
                  action="store_true", dest="use_external_config", default=False,
                  help="uses the external configs in './config.py'")
parser.add_option("-t", "--test",
                  action="store", dest="test", default="default",
                  help="sets the test to run")
parser.add_option("-U", "--disable-udp",
                  action="store_false", dest="udp", default=True,
                  help="disables UDP request")
parser.add_option("-T", "--disable-tcp",
                  action="store_false", dest="tcp", default=True,
                  help="disables TCP request")

(options, args) = parser.parse_args()

if options.use_external_config:
    from config import *
else:
    NO_PROXY = environ.get("NO_PROXY", "FALSE")
    SERVER_ADDR = environ.get("REMOTE_ADDR", "127.0.0.1")
    SERVER_PORT = int(environ.get("REMOTE_PORT", "25663"))
    MOCK_SERVER_ADDR = environ.get("MOCK_ADDR", "127.0.0.1")
    MOCK_SERVER_PORT = int(environ.get("MOCK_PORT", "5000"))
    MOCK_UDP_SERVER_ADDR = environ.get("MOCK_UDP_ADDR", "127.0.0.1")
    MOCK_UDP_SERVER_PORT = int(environ.get("MOCK_UDP_PORT", "6000"))
    MOCK_UDP_BUFFER_SIZE = int(environ.get("MOCK_UDP_BUFFER_SIZE", "65536"))
    TEST = environ.get("MOCK_TEST", options.test)
    SMALL_SIZE=256
    MEDIUM_SIZE=1024
    LARGE_SIZE=8192

def parse_size(size_string: str):
    if size_string.isdigit():
        return int(size_string)
    elif size_string[-1] in ["k", "K"] and size_string[:-1].isdigit():
        return int(size_string[:-1]) * 1024
    elif size_string[-1] in ["m", "M"] and size_string[:-1].isdigit():
        return int(size_string[:-1]) * 1024 * 1024
    elif size_string[-1] in ["g", "G"] and size_string[:-1].isdigit():
        return int(size_string[:-1]) * 1024 * 1024 * 1024
    else:
        return -1


def connect_to_socks(addr, port):
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, addr, port, True)
    socket.socket = socks.socksocket

def random_packet(size) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))

if NO_PROXY != "TRUE":
    connect_to_socks(SERVER_ADDR, SERVER_PORT)

try:
    if TEST == "default":
        if options.tcp:
            print("sending packet with a payload with size: 0")
            r = requests.get(f'http://{MOCK_SERVER_ADDR}:{MOCK_SERVER_PORT}')
            if r.json()["status"] == "up":
                print("SUCCESS")
            else:
                print("FAILED")
        exit(0)
    elif TEST == "no-body":
        if options.tcp:
            print("sending packet with a payload with size: 0")
            r = requests.get(f'http://{MOCK_SERVER_ADDR}:{MOCK_SERVER_PORT}')
            if r.json()["status"] == "up":
                print("SUCCESS")
            else:
                print("FAILED")
        exit(0)
    elif TEST == "small":
        size = SMALL_SIZE
    elif TEST == "medium":
        size = MEDIUM_SIZE
    elif TEST == "large":
        size = LARGE_SIZE
    else:
        size = parse_size(TEST)
        if size == -1:
            raise ValueError(f"Unable to parse size '{TEST}'")

    payload = base64.b64encode(random_packet(size).encode()).decode()

    if options.udp:
        print("sending udp packet with a payload with size:", size)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t2 = time.time()
        if udp_sock.sendto(payload.encode(), (MOCK_UDP_SERVER_ADDR, MOCK_UDP_SERVER_PORT)) == 0:
            print("UDP SEND FAILED")
        else:
            data, addr = udp_sock.recvfrom(MOCK_UDP_BUFFER_SIZE)
            t3 = time.time()
            if data == payload.encode():
                diff = t3 - t2
                print(f"UDP SUCCESS in {diff/2:0.6f} seconds with {size / diff / (1024 * 1024):0.2f} MBps")
            else:
                print("UDP FAILED")
    
    if options.tcp:
        print("sending tcp packet with a payload with size:", size)
        t0 = time.time()
        r = requests.post(f'http://{MOCK_SERVER_ADDR}:{MOCK_SERVER_PORT}', json={ "payload": payload })
        t1 = time.time()
        if r.json()["payload"] == payload:
            diff = t1 - t0
            print(f"TCP SUCCESS in {diff/2:0.6f} seconds with {size / diff / (1024 * 1024):0.2f} MBps")
        else:
            print("TCP FAILED")
except SystemExit as _:
    pass
except ...:
    print("FAILED")
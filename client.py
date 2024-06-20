import socket, socks, requests, random, string, base64, time
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-c", "--use-external-config",
                  action="store_true", dest="use_external_config", default=False,
                  help="uses the external configs in './config.py'")
parser.add_option("-t", "--test",
                  action="store", dest="test", default="default",
                  help="sets the test to run")

(options, args) = parser.parse_args()

if options.use_external_config:
    from config import *
else:
    SERVER_PORT=25663
    SERVER_ADDR="127.0.0.1"
    MOCK_SERVER_PORT=5000
    MOCK_SERVER_ADDR="127.0.0.1"
    SMALL_SIZE=256
    MEDIUM_SIZE=1024
    LARGE_SIZE=8192
    TEST=options.test

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

connect_to_socks(SERVER_ADDR, SERVER_PORT)

try:
    if TEST == "default":
        print("sending packet with a payload with size: 0")
        r = requests.get(f'http://{MOCK_SERVER_ADDR}:{MOCK_SERVER_PORT}')
        if r.json()["status"] == "up":
            print("SUCCESS")
        else:
            print("FAILED")
        exit(0)
    elif TEST == "no-body":
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


    print("sending packet with a payload with size:", size)
    payload = base64.b64encode(random_packet(size).encode()).decode()
    t0 = time.time()
    r = requests.post(f'http://{MOCK_SERVER_ADDR}:{MOCK_SERVER_PORT}', json={ "payload": payload })
    t1 = time.time()

    if r.json()["payload"] == payload:
        diff = t1 - t0
        print(f"SUCCESS in {diff/2:0.2f} with {size / diff / (1024 * 1024):0.2f} MBps")
    else:
        print("FAILED")
        print(payload)
        print(r.json()["payload"])
except ...:
    print("FAILED")
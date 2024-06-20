#!/bin/python3

from pytun import TunTapDevice, IFF_TUN
from struct import *
import socket, sys, time, fcntl

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        pack('256s', ifname[:15].encode())
    )[20:24])



tun = TunTapDevice(name='O_O', flags=IFF_TUN)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

host_ip = get_ip_address('wlo1')

print(tun.name)
tun.addr = '10.8.0.1'
tun.netmask = '255.255.255.0'
tun.mtu = 1500
tun.up()

while True:
    try:
        buf = tun.read(tun.mtu)
        ip_header_bytes = buf[4:24]
        ip_header = [*unpack('!BBHHHBBH4s4s', ip_header_bytes)]
        ip_version = ip_header[0] >> 4
        ihl = ip_header[0] & 0xf
        length = ip_header[2]
        ip_id = ip_header[3]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        if buf[-8:] == b"01234567":
            print(f"{ip_version}: {src_ip} -> {dst_ip} ({sys.byteorder})")
            print(len(ip_header_bytes))
            packet = buf[4:]
            print(socket.inet_ntoa(packet[12:16]))
            ip_header[8] = socket.inet_aton(host_ip)
            new_ip_header = pack('!BBHHHBBH4s', *ip_header[:-1])
            packet = new_ip_header + packet[16:]
            print(socket.inet_ntoa(packet[12:16]))
            s.sendto(packet, (dst_ip, 0))

        tun.write(buf)
    except KeyboardInterrupt:
        break
tun.close()





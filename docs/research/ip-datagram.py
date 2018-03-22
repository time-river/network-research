#!/usr/bin/env python3

import os
import fcntl
import select
import socket
import struct
from pyroute2 import IPRoute

TUN_PATH = "/dev/net/tun"
TUN_IFNAME = "tun0"
TUN_ADDRESS = "172.32.0.1"
TUN_ADDRESS_MASK = 24
TUN_TABLE = 100

MAIN_TABLE = 254

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
SIOCGIFMTU = 0x8921

def mtu_discovery(ifname):
    s = socket.socket(type=socket.SOCK_DGRAM)
    ifs = fcntl.ioctl(s, SIOCGIFMTU, struct.pack("16s16x", ifname))
    mtu = struct.unpack('<H', ifs[16:18])[0]
    print("MTU: ", mtu)
    return mtu

def monitor_prepare(ifname):
    ip = IPRoute()
    idx = ip.link_lookup(ifname=TUN_IFNAME)[0]
    ip.link('set', index=idx, state='up')
    ip.addr('add', index=idx, address=TUN_ADDRESS, mask=TUN_ADDRESS_MASK)
    ip.route('add', dst="0.0.0.0", mask=0, gateway=TUN_ADDRESS, table=TUN_TABLE)
    ip.rule('add', table=MAIN_TABLE, priority=10, iifname=TUN_IFNAME, action='FR_ACT_TO_TBL')
    ip.rule('add', table=TUN_TABLE, priority=100, action='FR_ACT_TO_TBL')
    os.system("sysctl -w net.ipv4.conf.{}.accept_local=1".format(TUN_IFNAME))


def tun_alloc(ifname):
    ftun = os.open(TUN_PATH, os.O_RDWR)
    fcntl.ioctl(ftun, TUNSETIFF, struct.pack("16sH", ifname, IFF_TUN | IFF_NO_PI))
    mtu = mtu_discovery(ifname)
    return ftun, mtu

def loop(fd, mtu):
    F_GETFL = fcntl.F_GETFL
    flag = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flag|os.O_NONBLOCK)
    flag = fcntl.fcntl(fd, fcntl.F_GETFL)
    if flag & os.O_NONBLOCK:
        print("fd set O_NONBLOCK")

    epoll = select.epoll()
    epoll.register(fd, select.EPOLLIN)

    while True:
        connections = {}; requests = {}; responses = {}
        events = epoll.poll(1)
        for fileno, event in events:
            if event & select.EPOLLIN:
                print("EPOLLIN")
                packet = os.read(fileno, mtu)
                size = len(packet)
                version = struct.unpack('!c', packet[0:1])[0]
                protocol = struct.unpack('!c', packet[9:10])[0]
                src = struct.unpack('!4s', packet[12:16])[0]
                dst = struct.unpack('!4s', packet[16:20])[0]
                print("size={:d}, version_ihl=0x{:s}, protocol=0x{:s}, src={:s}, dst={:s}".format(
                        size, version.hex(), protocol.hex(), socket.inet_ntoa(src), socket.inet_ntoa(dst)))
                os.write(fd, packet)
            elif event & select.EPOLLOUT:
                print("EPOLLOUT")
                data = os.read(fineno, 1024)
                print(len(data), data)
 
if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Need root privileges.")
        exit(0)

    ftun, mtu = tun_alloc(TUN_IFNAME.encode())
    monitor_prepare(TUN_IFNAME)
    loop(ftun, mtu)

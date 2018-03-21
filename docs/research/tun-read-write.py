#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
a simple program which could print all package of content sended from local machine

prepare:
    # ip tuntap add mode tun tun0
    # ip link set tun0 up
    # ip addr add 10.0.0.2/24 dev tun0
    # ip route add default via 10.0.0.2 dev tun0 table 100 # ip rule add from all lookup 100 
    # ip rule add from all iif tun0 lookup main

reference:
    feasibility
        https://github.com/alwaystest/Blog/issues/20
        https://stackoverflow.com/questions/2664955/can-i-make-a-tcp-packet-modifier-using-tun-tap-and-raw-sockets
        https://serverfault.com/questions/671516/what-exactly-happens-to-packets-written-to-a-tun-tap-device

    example
        http://ct2wj.com/2016/02/28/shadowsocks-android-source-code-analysis/
        https://stackoverflow.com/questions/45794992/send-raw-ip-packet-with-tun-device

    matter
        https://serverfault.com/questions/411921/how-to-configure-linux-routing-filtering-to-send-packets-out-one-interface-over

      IP packet max size
        https://serverfault.com/questions/645890/tcpdump-truncates-to-1472-bytes-useful-data-in-udp-packets-during-the-capture
        https://gist.github.com/nzjrs/8934855
'''

import select
import os
import socket
import fcntl
from fcntl import ioctl
import struct

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
SIOCGIFMTU = 0x8921

def mtu_discovery(ifname):
    s = socket.socket(type=socket.SOCK_DGRAM)
    ifs = ioctl(s, SIOCGIFMTU, struct.pack("16s16x", ifname))
    mtu = struct.unpack('<H',ifs[16:18])[0]
    print("MTU: ", mtu)
    return mtu
    
def read_all_data_from_tun():
    pass

def loop(fd, mtu):
    flag = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flag|os.O_NONBLOCK)
    flag = fcntl.fcntl(fd, fcntl.F_GETFL)
    if flag & os.O_NONBLOCK:
        print("O_NONBLOCK")

    epoll = select.epoll()
    epoll.register(fd, select.EPOLLIN)

    while True:
        connections = {}; requests = {}; responses = {}
        events = epoll.poll(1)
        for fileno, event in events:
            if event & select.EPOLLIN:
                print("EPOLLIN")
                data = os.read(fileno, mtu)
                print(len(data), data)
                os.write(fd, data)
            elif event & select.EPOLLOUT:
                print("EPOLLOUT")
                data = os.read(fineno, 1024)
                print(len(data), data)

if __name__ == '__main__':
    ifname = b'tun0'
    ftun = os.open("/dev/net/tun", os.O_RDWR)
    ifs = ioctl(ftun, TUNSETIFF, struct.pack("16sH", ifname, IFF_TUN | IFF_NO_PI))
    mtu = mtu_discovery(ifname)
    loop(ftun, mtu)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
a simple program which could print all package of content sended from local machine

prepare:
    # ip tuntap add mode tun tun0
    # ip link set tun0 up
    # ip addr add 10.0.0.2/24 dev tun0
    # ip route add default via 10.0.0.2 dev tun0 table 100
    # ip rule add from all lookup 100 
    # ip rule add from all iif tun0 lookup main

reference:
    feasibility
        https://stackoverflow.com/questions/2664955/can-i-make-a-tcp-packet-modifier-using-tun-tap-and-raw-sockets
        https://serverfault.com/questions/671516/what-exactly-happens-to-packets-written-to-a-tun-tap-device

    example
        http://ct2wj.com/2016/02/28/shadowsocks-android-source-code-analysis/
        https://stackoverflow.com/questions/45794992/send-raw-ip-packet-with-tun-device

    matter
        https://serverfault.com/questions/411921/how-to-configure-linux-routing-filtering-to-send-packets-out-one-interface-over
'''

import select
import os
import fcntl
from fcntl import ioctl
import struct

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000


def parse_header():
    pass

def loop(fd):
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
                data = os.read(fileno, 1024*1024) # too big package may be result error
                print(len(data), data)
                os.write(fd, data)
            elif event & select.EPOLLOUT:
                print("EPOLLOUT")
                data = os.read(fineno, 1024)
                print(len(data), data)

if __name__ == '__main__':
    ftun = os.open("/dev/net/tun", os.O_RDWR)
    ioctl(ftun, TUNSETIFF, struct.pack("16sH", b"tun0", IFF_TUN | IFF_NO_PI))
    loop(ftun)

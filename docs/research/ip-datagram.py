#!/usr/bin/env python3

import os
import fcntl
import select
import socket
import struct
from radix import Radix
from pyroute2 import IPRoute


TUN_PATH = "/dev/net/tun"
TUN_IFNAME = "tun0"
TUN_ADDRESS = "172.32.0.1"
TUN_ADDRESS_MASK = 24
TUN_TABLE = 100

MAIN_TABLE = 254

IP_FILE = "ip_list.txt"
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
SIOCGIFMTU = 0x8921

def mtu_discovery(ifname):
    '''
    find the MTU(maximum transmission unit) of tun device <ifname>,
    which is the maximum bytes read from tun device <ifname>.
    '''
    s = socket.socket(type=socket.SOCK_DGRAM)
    ifs = fcntl.ioctl(s, SIOCGIFMTU, struct.pack("16s16x", ifname))
    mtu = struct.unpack('<H', ifs[16:18])[0]
    print("MTU: ", mtu)
    return mtu

def monitor_prepare(ifname):
    '''
    1. setup tun device <ifname>
    2. assign IPv4 address to tun device <ifname>
    3. add route rules
    3. configure linux kernel to receive IP packet from local device <ifname>

    like command:
        $sudo ip link set tun0 up
        $sudo ip addr add 172.32.0.1/24 dev tun0
        $sudo ip route add default via 172.32.0.1 dev tun0 table 100
        $sudo ip rule add from all pref 100 lookup 100
        $sudo ip rule add from all iif tun0 pref 10 lookup main
        $sudo sysctl -w net.ipv4.conf.tun0.accept_local=1

    '''
    ip = IPRoute()
    idx = ip.link_lookup(ifname=ifname)[0]
    ip.link('set', index=idx, state='up')
    ip.addr('add', index=idx, address=TUN_ADDRESS, mask=TUN_ADDRESS_MASK)
    ip.route('add', dst="0.0.0.0", mask=0, gateway=TUN_ADDRESS, table=TUN_TABLE)
    ip.rule('add', table=MAIN_TABLE, priority=10, iifname=TUN_IFNAME, action='FR_ACT_TO_TBL')
    ip.rule('add', table=TUN_TABLE, priority=100, action='FR_ACT_TO_TBL')
    os.system("sysctl -w net.ipv4.conf.{}.accept_local=1".format(TUN_IFNAME))

def clean_prepare(ifname):
    '''
    clean `monitor_prepare` configurations
    '''
    ip = IPRoute()
    idx = ip.link_lookup(ifname=ifname)[0]
    ip.rule('del', table=TUN_TABLE, priority=100, action='FR_ACT_TO_TBL')
    ip.rule('del', table=MAIN_TABLE, priority=10, iifname=TUN_IFNAME, action='FR_ACT_TO_TBL')
    ip.route('del', dst="0.0.0.0", mask=0, gateway=TUN_ADDRESS, table=TUN_TABLE)

def tun_alloc(ifname):
    '''
    alloc tun device named <ifname>, the tun device will disappear after the program exit.

    like command:
        $sudo ip tuntap add mode tun name tun0
    '''
    ftun = os.open(TUN_PATH, os.O_RDWR)
    fcntl.ioctl(ftun, TUNSETIFF, struct.pack("16sH", ifname, IFF_TUN | IFF_NO_PI))
    mtu = mtu_discovery(ifname)
    return ftun, mtu

def route_prepare(rtree, ips):
    '''
    build the radix tree which is used to match destination ip
    '''
    for ip in ips:
        a = ip.strip()
        print(a)
        if a[0] == '!':
            rnode = rtree.add(a.strip("! \t\n"))
            rnode.data['result'] = False
        else:
            rnode = rtree.add(a)
            rnode.data['result'] = True

def route_match(rtree, ip):
    '''
    match destination ip
    '''
    rnode = rtree.search_best(ip)
    if rnode is not None:
        return rnode.data['result']
    else:
        return False

def loop(fd, mtu, rtree):
    '''
    receive data from <fd>, print
        data length,
        IP version and IP header length,
        encapsulated packet protocol,
        source ip,
        destination ip,
        destination ip whether match in ip stored in file 'ip_list.txt'

    it seems just EPOLLIN event...
    '''
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
                packet = os.read(fileno, mtu)
                size = len(packet)
                version = struct.unpack('!c', packet[0:1])[0]
                protocol = struct.unpack('!c', packet[9:10])[0]
                src = struct.unpack('!4s', packet[12:16])[0]
                dst = struct.unpack('!4s', packet[16:20])[0]
                if route_match(rtree, socket.inet_ntoa(dst)):
                    match = "match ip_list"
                else:
                    match = "not match ip_list"
                print("size={:d}, version_ihl=0x{:s}, protocol=0x{:s}, src={:s}, dst={:s}, {}".format(
                        size, version.hex(), protocol.hex(), socket.inet_ntoa(src), socket.inet_ntoa(dst), match))
                os.write(fd, packet)
            elif event & select.EPOLLOUT:
                print("EPOLLOUT")
                packet = os.read(fineno, 1024)
                print(len(packet), packet)
 
if __name__ == '__main__':
    rtree = Radix()
    if os.geteuid() != 0:
        print("Need root privileges.")
        exit(0)

    ftun, mtu = tun_alloc(TUN_IFNAME.encode())
    with open(IP_FILE) as f:
        route_prepare(rtree, f.readlines())
    try:
        monitor_prepare(TUN_IFNAME)
        loop(ftun, mtu, rtree)
    except:
        clean_prepare(TUN_IFNAME)

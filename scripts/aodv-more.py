# A more complete implementation of AODV at the user-level that includes queueing packets to destinations without routes
# and interaction with the IP layer and Kernel to accomplish that
# caution: there may be bugs -- this code has not been tested, it is primarily meant to be an illustration

#!/usr/bin/env python3

import socket
import select
import time
import threading
import os
import fcntl
import struct
from pyroute2 import IPRoute

from core.api.grpc import client
from core.api.grpc import core_pb2
import xmlrpc.client

# Constants
AODV_PORT = 654
RREQ_TYPE = 1
RREP_TYPE = 2
RERR_TYPE = 3
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Setup TUN Interface
def tun_setup(name='tun0'):
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

# Route Entry
class RouteEntry:
    def __init__(self, next_hop, seq_num, hop_count, lifetime):
        self.next_hop = next_hop
        self.seq_num = seq_num
        self.hop_count = hop_count
        self.lifetime = lifetime

# AODV Daemon
class AODVDaemon:
    def __init__(self, iface='eth0'):
        self.iface = iface
        self.seq_num = 0
        self.route_table = {}
        self.packet_queue = {}
        self.sock = None
        self.running = False
        self.tun_fd = tun_setup()
        self.iproute = IPRoute()
        self.netlink_events = []
        self.seen_rreqs = set()

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', AODV_PORT))
        self.running = True
        threading.Thread(target=self._main_loop, daemon=True).start()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

    def _main_loop(self):
        self.sock.setblocking(False)
        poll_interval = 0.5

        while self.running:
            rlist, _, _ = select.select([self.sock, self.tun_fd], [], [], poll_interval)
            if self.sock in rlist:
                data, addr = self.sock.recvfrom(4096)
                self._handle_aodv_packet(data, addr)

            if self.tun_fd in rlist:
                packet = os.read(self.tun_fd, 65535)
                dest_ip = socket.inet_ntoa(packet[16:20])
                if dest_ip not in self.route_table:
                    self.packet_queue.setdefault(dest_ip, []).append(packet)
                    self.netlink_events.append(dest_ip)
                else:
                    self._send_packet_out(packet, dest_ip)

            while self.netlink_events:
                dest_ip = self.netlink_events.pop(0)
                self._initiate_route_discovery(dest_ip)

    def _handle_aodv_packet(self, data, addr):
        if not data: return
        msg_type = data[0]
        src_seq = int.from_bytes(data[1:5], byteorder='big')
        payload = data[5:].decode().split()
        if msg_type == RREQ_TYPE: self._process_rreq(src_seq, payload, addr)
        elif msg_type == RREP_TYPE: self._process_rrep(src_seq, payload, addr)

    def _process_rreq(self, src_seq, payload, addr):
        orig_ip, dest_ip, hop_count = payload[0], payload[1], int(payload[2])
        rreq_id = (orig_ip, dest_ip, src_seq)
        if rreq_id in self.seen_rreqs: return
        self.seen_rreqs.add(rreq_id)
        self._update_route(orig_ip, addr[0], src_seq, hop_count)
        if self._is_ours(dest_ip): self._send_rrep(dest_ip, orig_ip, hop_count+1)

    def _process_rrep(self, src_seq, payload, addr):
        dest_ip, orig_ip, hop_count = payload[0], payload[1], int(payload[2])
        self._update_route(dest_ip, addr[0], src_seq, hop_count)
        self._install_route(dest_ip)
        if dest_ip in self.packet_queue:
            for pkt in self.packet_queue.pop(dest_ip):
                self._send_packet_out(pkt, dest_ip)

    def _update_route(self, dest_ip, next_hop, seq_num, hop_count):
        self.route_table[dest_ip] = RouteEntry(next_hop, seq_num, hop_count, time.time()+60)

    def _install_route(self, dest_ip):
        next_hop = self.route_table[dest_ip].next_hop
        oif = self.iproute.link_lookup(ifname=self.iface)[0]
        self.iproute.route('add', dst=f'{dest_ip}/32', gateway=next_hop, oif=oif)

    def _send_packet_out(self, packet, dest_ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(packet, (dest_ip, 0))

    def _is_ours(self, ip): return ip == "192.168.1.100"

    def _initiate_route_discovery(self, dest_ip):
        self.seq_num += 1
        orig_ip = "192.168.1.100"
        msg = bytearray([RREQ_TYPE]) + self.seq_num.to_bytes(4, 'big')
        msg += f"{orig_ip} {dest_ip} 1".encode()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.sendto(msg, ('255.255.255.255', AODV_PORT))

def configure_tun_interface():
    cmds = ["ip tuntap add dev tun0 mode tun", "ip addr add 10.0.0.1/24 dev tun0",
            "ip link set dev tun0 up", "ip route add default dev tun0"]
    for cmd in cmds: os.system(cmd)

if __name__ == "__main__":
    configure_tun_interface()
    daemon = AODVDaemon(iface='eth0')
    daemon.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        daemon.stop()


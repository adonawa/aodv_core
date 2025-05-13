#!/usr/bin/python
import sys
import struct
import socket
import math
import time
import argparse
import glob
import subprocess
import threading
import datetime
import select


from core.api.grpc import client
from core.api.grpc import core_pb2
import xmlrpc.client
thrdlock = threading.Lock()
xmlproxy = xmlrpc.client.ServerProxy("http://localhost:8000", allow_none=True)


AODV_PORT = 654               # Well-known UDP port for AODV control
NETLINK_AODV = 30             # Dummy netlink protocol number (example)
RREQ_TYPE    = 1
RREP_TYPE    = 2
RERR_TYPE    = 3
mcastaddr = '235.1.1.1' # multicast addresss
ttl = 64


TARGET_NODE = 4
message_recieved = 0

def msg_type_toString(msg_type):
    msg_str = {
        RREQ_TYPE:"RREQ",
        RREP_TYPE:"RREP",
        RERR_TYPE:"RERR"
    }
    return msg_str.get(msg_type, "Could not parse message type.")

class RouteEntry:
    def __init__(self, next_hop, seq_num, hop_count, lifetime):
        self.next_hop   = next_hop
        self.seq_num    = seq_num
        self.hop_count  = hop_count
        self.lifetime   = lifetime  # e.g., time at which route expires

class Node:
    def __init__(self, node_id, ip, iface='eth0'):
        self.iface = iface
        self.node_id = node_id
        self.seq_num = 0
        self.route_table = {}
        self.netlink_events = []
        self.seen_rreqs = set()
        self.seen_rreps = set()
        self.ip = ip

        self.sock = None
        self.running = False

    def start(self):
        """
        Initialize UDP socket, begin main loop in a separate thread.
        """
        # self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_group_setup()
        self.sock.bind(('', AODV_PORT))
        self.running = True
        print(f"[AODV] Listening for AODV packets on UDP port {AODV_PORT}...")
        threading.Thread(target=self._main_loop, daemon=True).start()

    def stop(self):
        """
        Stop the daemon.
        """
        self.running = False
        if self.sock:
            self.sock.close()

       

    def socket_group_setup(self):
        addrinfo = socket.getaddrinfo(mcastaddr, AODV_PORT)[0]
        self.sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    
    def socket_broadcast_setup(self):
        ttl_bin = struct.pack('@i', ttl)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

    def _main_loop(self):
        """
        Main event loop to receive and process AODV messages or route-needed events.
        """
        global message_recieved
        self.sock.setblocking(False)
        poll_interval = 0.5  # seconds
        while self.running:
            # Use select to see if we have incoming data on our UDP socket
            rlist, _, _ = select.select([self.sock], [], [], poll_interval)
            # rlist coming up empty. (not grabbing self.sock info?)
            if self.sock in rlist:
                message_recieved += 1 
                data, addr = self.sock.recvfrom(4096)
                self.handle_aodv_packet(data, addr)

            # Check for any netlink (route-needed) events
            while self.netlink_events:
                dest_ip = self.netlink_events.pop(0)
                print(f"[AODV] Netlink event: route needed for {dest_ip}")
                self.initiate_route_discovery(dest_ip)

    def handle_aodv_packet(self, data, addr):
        global message_recieved
        if not data:
            return
        msg_type = data[0]

        try:
            src_seq = int.from_bytes(data[1:5], byteorder='big')
            payload = data[5:].decode('utf-8', errors='ignore')
        except Exception:
            print("[AODV] Failed to parse incoming packet.")
            return
        if msg_type == RREQ_TYPE:
            self.process_rreq(src_seq, payload, addr)
        elif msg_type == RREP_TYPE: 
            self.process_rrep(src_seq, payload, addr)
        elif msg_type == RERR_TYPE: 
            self.process_rerr(payload, addr)
        else:
            print(f"[AODV] Unknown message type {msg_type} from {addr}")
    

    def process_rerr(self, payload, addr):
        if not payload:
            return
        unreachable_ip = payload
        print(f"[AODV] RERR: Unreachable {unreachable_ip} reported by {addr}")
        if unreachable_ip in self.route_table:
            del self.route_table[unreachable_ip]
            print(f"[AODV] Route to {unreachable_ip} removed.")

    def send_rerr(self, unreachable_ip):
        msg = bytearray([RERR_TYPE])
        #placeholder
        dest_seq_bytes = self.seq_num.to_bytes(4, byteorder='big')
        payload_str = f"{unreachable_ip}"
        msg += dest_seq_bytes
        msg += payload_str.encode('utf-8', errors='ignore')
        self.socket_broadcast_setup()
        self.sock.sendto(msg, (mcastaddr, AODV_PORT))
        print(f"[AODV] RERR broadcast for {unreachable_ip}")

    def process_rreq(self, src_seq, payload, addr):
        print(f"[AODV] Received RREQ from {payload[0]}")
        parts = payload.strip().split()
        if len(parts) < 3:
            return
        
        orig_ip, dest_ip, hop_str = parts
        hop_count = int(hop_str)
        rreq_id = (orig_ip, dest_ip, src_seq)
        if rreq_id in self.seen_rreqs:
            return
        self.seen_rreqs.add(rreq_id)
        print(f"[AODV] RREQ from {orig_ip} -> {dest_ip}, hop={hop_count}, seq={src_seq}")

        # Update our route to the originator (reverse route)
        self.update_route(orig_ip, addr[0], src_seq, hop_count)

        # Check if we are the destination or if we have a route for the destination
        if self.is_ours(dest_ip):
            print("Destination has been reached")
            self.send_rrep(dest_ip, orig_ip, 1, src_seq)
        elif dest_ip in self.route_table:
            known_route = self.route_table[dest_ip]
            self.send_rrep(dest_ip, orig_ip, self.route_table[dest_ip].hop_count + 1, self.route_table[dest_ip].seq_num)
        else:
            self.forward_rreq(orig_ip, dest_ip, src_seq, hop_count + 1 )

    
    def process_rrep(self,src_seq, payload, addr):
        parts = payload.strip().split()
        if len(parts) < 3: 
            return
        dest_ip, orig_ip, hop_str = parts
        hop_count = int(hop_str)
        

        print(f"[AODV] RREP: {dest_ip} -> {orig_ip}, hop={hop_count}")

        self.update_route(dest_ip, addr[0], src_seq, hop_count)

        if self.is_ours(orig_ip):
            print(f"[AODV] We are the originator for RREP to {dest_ip}. Route established!")
        else:
            next_hop = self.get_route_next_hop(orig_ip)
            if next_hop:
                self.send_rrep(dest_ip, orig_ip, hop_count + 1, src_seq, next_hop)
            else:
                print(f"[AODV] No route to forward RREP to {orig_ip}??")

    
    def forward_rreq(self, orig_ip, dest_ip, src_seq, hop_count):
        print(f"[AODV] Forwarding RREQ for {orig_ip}->{dest_ip}, hop={hop_count}")
        msg = bytearray([RREQ_TYPE])
        msg += src_seq.to_bytes(4, byteorder='big')
        payload_str = f"{orig_ip} {dest_ip} {hop_count}"
        msg += payload_str.encode('utf-8', errors='ignore')
        self.socket_broadcast_setup()
        self.sock.sendto(msg, (mcastaddr, AODV_PORT))



    def send_rrep(self, dest_ip, orig_ip, hop_count, src_seq, next_hop = None):
        if next_hop is None:
            next_hop = self.get_route_next_hop(orig_ip)
            if not next_hop:
                print(f"[AODV] send_rrep: No route to origin {orig_ip}, cannot send RREP.")
                return
        msg = bytearray([RREP_TYPE])
        dest_seq_bytes = src_seq.to_bytes(4, byteorder='big')
        payload_str = f"{dest_ip} {orig_ip} {hop_count}"
        msg += dest_seq_bytes
        msg += payload_str.encode('utf-8', errors='ignore')
        self.socket_broadcast_setup()
        print(f"[AODV] Sending RREP {dest_ip}->{orig_ip}, next_hop={next_hop}")
        self.sock.sendto(msg, (next_hop, AODV_PORT))




    def get_route_next_hop(self, dest_ip):
        if dest_ip in self.route_table:
            return self.route_table[dest_ip].next_hop        


    
    def update_route(self, dest_ip, next_hop, seq_num, hop_count):
        lifetime = time.time() + 20.0  # 1 minute 20 sec
        entry = RouteEntry(next_hop, seq_num, hop_count, lifetime)
        self.route_table[dest_ip] = entry
        print(f"[AODV] Route updated: {dest_ip} via {next_hop}, hop={hop_count}, seq={seq_num}")


        


    def initiate_route_discovery(self, dest_ip):
        self.seq_num += 1
        hop_count = 1
        orig_ip = self.get_own_ip()
        msg = bytearray([RREQ_TYPE])
        msg += self.seq_num.to_bytes(4, byteorder='big')
        payload_str = f"{orig_ip} {dest_ip} {hop_count}"
        msg += payload_str.encode('utf-8', errors='ignore')
        print(f"[AODV] Initiating route discovery for {dest_ip}")
        rreq_id = (orig_ip, dest_ip, self.seq_num)
        self.seen_rreqs.add(rreq_id)

        self.socket_broadcast_setup() 
        self.sock.sendto(msg, (mcastaddr, AODV_PORT))
    


    def get_own_ip(self):
        return self.ip
    
    def is_ours(self, ip):
        return self.ip == ip




def main():
    global my_node
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','-my-id', dest = 'node_id', metavar='my id',
                    type=str, default = '1', help='My Node ID')
    #CORE
    core = client.CoreGrpcClient("172.16.0.254:50051")
    core.connect()
    response = core.get_sessions()
    if not response.sessions:
        raise ValueError("no current core sessions\n")
    session_summary = response.sessions[0]
    session_id = int(session_summary.id)
    session = core.get_session(session_id).session

    args = parser.parse_args()
    source_id = int(args.node_id)

    core_node_info = core.get_node(session_id, source_id)
    iface = core_node_info.ifaces[0]
    ip = iface.ip4
    print(f"[Start] Node #{source_id} IP address is: {ip}")
    my_node = Node(source_id, ip)
    #CORE 

    # recvthrd = ReceiveUDPThread()
    # recvthrd.start()
    my_node.start()

    try: 
       while True:
            cmd = input("> ").strip()
            if cmd == "exit":
                break
            elif cmd == "reboot":
                for unreachable_ip in my_node.route_table: 
                    my_node.send_rerr(unreachable_ip)
                my_node.route_table.clear()
            elif cmd == "routes":
                print(f"Printing routes for {my_node.node_id}...\n")
                for k, v in my_node.route_table.items():
                    print(f"  {k} -> next_hop={v.next_hop}, seq={v.seq_num}, hop={v.hop_count}, expires={time.ctime(v.lifetime)}")
            elif cmd.startswith("needroute"):
                parts = cmd.split()
                if len(parts) == 2:
                    target = parts[1]
                    if target in my_node.route_table:
                        print(f"Route to {target} has already been established")
                        continue
                    my_node.netlink_events.append(target)                    
                    # initiate_route_discovery(my_node.node_id, target)
                else:
                    my_node.netlink_events.append(TARGET_NODE)
                    # initiate_route_discovery(my_node.node_id, TARGET_NODE)
            else:
                print("Unknown command. Please try again.\n")
    except KeyboardInterrupt:
        pass
    finally:
        print("[AODV] Stopping aodv script...")
        my_node.stop()



















if __name__ == "__main__":
   main()
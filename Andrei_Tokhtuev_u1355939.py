# # Copyright 2013 Andrei Tokhtuev
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at:
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

# """
# A skeleton POX component

# You can customize this to do whatever you like.  Don't forget to
# adjust the Copyright above, and to delete the Apache license if you
# don't want to release under Apache (but consider doing so!).

# Rename this file to whatever you like, .e.g., mycomponent.py.  You can
# then invoke it with "./pox.py mycomponent" if you leave it in the
# ext/ directory.

# Implement a launch() function (as shown below) which accepts commandline
# arguments and starts off your component (e.g., by listening to events).

# Edit this docstring and your launch function's docstring.  These will
# show up when used with the help component ("./pox.py help --mycomponent").
# """

# # Import some POX stuff
# from pox.core import core                     # Main POX object
# import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
# import pox.lib.packet as pkt                  # Packet parsing/construction
# from pox.lib.addresses import EthAddr, IPAddr # Address types
# import pox.lib.util as poxutil                # Various util functions
# import pox.lib.revent as revent               # Event library
# import pox.lib.recoco as recoco               # Multitasking library

# # Create a logger for this component
# log = core.getLogger()

# # Mapping between virtual IP and real IP
# SERVER_VIRTUAL_IP = IPAddr("10.0.0.10")
# REAL_SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # List of real server IPs
# REAL_SERVER_MACS = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]  # Corresponding MACs

# # Round-robin state (a simple counter to alternate between servers)
# round_robin_index = 0

# @poxutil.eval_args

# def launch():
#     """
#     Launch the POX component, listen to switches, and handle ARP requests and ICMP traffic.
#     """
#     core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
#     core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
#     log.info("POX controller running with ARP interception and virtual IP mapping.")
#   # When your component is specified on the commandline, POX automatically
#   # calls this function.

# # Event handler for when a switch connects
# def _handle_ConnectionUp(event):
#     log.info(f"Switch {event.dpid} has connected")


# def _handle_PacketIn(event):
#     packet = event.parsed

#     if packet.type == pkt.ethernet.ARP_TYPE:
#         arp = packet.payload
#         if arp.opcode == pkt.arp.REQUEST:
#             log.info(f"Intercepted ARP request for {SERVER_VIRTUAL_IP}. Client IP: {arp.protosrc}, Client MAC: {arp.hwsrc}")

#             # Pick the next server for the client using round-robin
#             client_IP = arp.protosrc
#             real_server_ip, server_mac = get_next_server_ip_and_mac()

#             # Log selected real server IP and MAC
#             log.info(f"Selected real server: {real_server_ip} with MAC {server_mac}")

#             # Send an ARP reply for the virtual IP (10.0.0.10)
#             # arp_reply = pkt.arp()
#             # arp_reply.opcode = pkt.arp.REPLY
#             # arp_reply.hwsrc = server_mac  # Virtual MAC
#             # arp_reply.hwdst = arp.hwsrc   # Client's MAC
#             # arp_reply.protosrc = SERVER_VIRTUAL_IP # Virtual IP
#             # arp_reply.protodst = arp.protosrc      # Client's IP
            
#             # arp_responder code
#             a = packet.find('arp')
#             r = pkt.arp()
#             r.hwtype = a.hwtype
#             r.prototype = a.prototype
#             r.hwlen = a.hwlen
#             r.protolen = a.protolen
#             r.opcode = arp.REPLY
#             r.hwdst = a.hwsrc
#             r.protodst = a.protosrc
#             r.protosrc = SERVER_VIRTUAL_IP
#             mac = a.hwsrc
#             r.hwsrc = server_mac
#             # mac = event.connection.eth_addr # Maybe this instead? 
#             e = pkt.ethernet(type=packet.type, src=event.connection.eth_addr,
#                         dst=a.hwsrc)
#             e.payload = r
#             # if packet.type == pkt.ethernet.VLAN_TYPE:
#             #     v_rcv = packet.find('vlan')
#             #     e.payload = pkt.vlan(eth_type = e.type,
#             #                     payload = e.payload,
#             #                     id = v_rcv.id,
#             #                     pcp = v_rcv.pcp)
#             #     e.type = pkt.ethernet.VLAN_TYPE
#             msg = of.ofp_packet_out()
#             msg.data = e.pack()
#             msg.actions.append(of.ofp_action_output(port =
#                                                     of.OFPP_IN_PORT))
#             msg.in_port = event.port
#             event.connection.send(msg)

#              # Log the ARP reply details
#             # log.info(f"Creating ARP reply: Source IP: {arp_reply.protosrc}, Dest IP: {arp_reply.protodst}, Source MAC: {arp_reply.hwsrc}, Dest MAC: {arp_reply.hwdst}")

#             # Install the flow rule for the client -> server mapping
#             install_flow_rule(event, client_IP, real_server_ip)

#             # Construct the Ethernet frame
#             # ether = pkt.ethernet()
#             # ether.type = pkt.ethernet.ARP_TYPE
#             # ether.dst = packet.src # Client's MAC
#             # ether.src = server_mac # Server's MAC
#             # ether.payload = arp_reply

#             # # Send ARP reply
#             # event.connection.send(ether.pack()) 
#             # log.info(f"Sent ARP reply to {arp.protosrc} for {SERVER_VIRTUAL_IP}.")

# def install_flow_rule(event, client_IP, real_server_ip):
#     """
#     Install the flow rule dynamically based on the client IP and selected real server IP
#     """

#     client_in_port = parsePortFromIP(client_IP)
#     server_in_port = parsePortFromIP(real_server_ip)

#     # Log the flow rule installation details
#     log.info(f"Installing flow rules: Client IP: {client_IP}, Real Server IP: {real_server_ip}, Client Port: {client_in_port}, Server Port: {server_in_port}")

#     ## Template 
#     # msg = of.ofp_flow_mod()
#     # msg.match.in_port = # Switch port number the packet arrived on
#     # msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
#     # msg.match.nw_dst = # IP destination address
#     # msg.match.nw_src = # IP source address (only in the server to client message handler)
#     # msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip)) # Rule

#     # Flow rule for client to real server
#     msg = of.ofp_flow_mod()
#     msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
#     msg.match.in_port = client_in_port  # Client port 
#     msg.match.nw_dst = SERVER_VIRTUAL_IP
#     # Modify the destination IP field to the real server IP
#     msg.actions.append(of.ofp_action_nw_addr.set_dst(real_server_ip))  # Set destination IP
#     # Forward to the real server's port
#     msg.actions.append(of.ofp_action_output(port=server_in_port))  # Send to server
#     event.connection.send(msg)
#     log.info(f"Installed flow rule for client -> server: {client_IP}(port: {client_in_port}) -> {real_server_ip}(port: {server_in_port})")

#     # Flow rule for server to client (reverse direction)
#     msg = of.ofp_flow_mod()
#     msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
#     msg.match.in_port = server_in_port  # Server port 
#     msg.match.nw_dst = client_IP  # h1's IP
#     msg.match.nw_src = real_server_ip
#      # Modify the source IP field to the virtual IP
#     msg.actions.append(of.ofp_action_nw_addr.set_src(SERVER_VIRTUAL_IP))  # Set source IP to virtual IP
#     # Forward the packet back to the client
#     msg.actions.append(of.ofp_action_output(port=client_in_port))  # Send back to the client
#     event.connection.send(msg)
#     log.info(f"Installed flow rule for server -> client: {real_server_ip}(port: {server_in_port}) -> {client_IP}(port: {client_in_port})")

#   # Store previous state so that round-robin works correctly
# def get_next_server_ip_and_mac():
#     global round_robin_index
#     # Get the current server IP and MAC using round-robin
#     server_ip = REAL_SERVER_IPS[round_robin_index]
#     server_mac = REAL_SERVER_MACS[round_robin_index]
#     round_robin_index = (round_robin_index + 1) % len(REAL_SERVER_IPS)  # Cycle through the servers
#     return server_ip, server_mac

# def parsePortFromIP(client_IP):
#     # Split the IP address by periods ('.') to get each part
#     ip_parts = str(client_IP).split('.')
    
#     # Get the last part of the IP (which corresponds to the port number)
#     last_part = ip_parts[-1]
    
#     # Return the integer value of the last part, which represents the port number
#     return int(last_part)


# Virtual IP Load Balancing Switch for POX
from pox.core import core
from pox.lib.packet import arp, icmp, ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.openflow import libopenflow_01 as of
import random

log = core.getLogger()

# Virtual IP and Real IP addresses of servers
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # Real IPs of servers h5 and h6
MAC_ADDRESSES = {  # MAC addresses corresponding to the servers
    "10.0.0.5": EthAddr("00:00:00:00:00:05"),
    "10.0.0.6": EthAddr("00:00:00:00:00:06"),
}

# Round-robin index for selecting a server
server_index = 0

def handle_arp_request(event):
    global server_index

    # Parse the ARP request
    packet = event.parsed
    if packet.type == ethernet.ARP_TYPE:
        arp_packet = packet.payload
        if arp_packet.opcode == arp.REQUEST:
            # If the request is for our virtual IP
            if arp_packet.dst_ip == VIRTUAL_IP:
                # Select the next server in round-robin fashion
                selected_server_ip = SERVER_IPS[server_index]
                server_index = (server_index + 1) % len(SERVER_IPS)

                # Create ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = MAC_ADDRESSES[str(selected_server_ip)]
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = arp.REPLY
                arp_reply.src_ip = selected_server_ip
                arp_reply.dst_ip = arp_packet.src_ip

                # Create Ethernet frame
                ethernet_reply = ethernet()
                ethernet_reply.set_src(MAC_ADDRESSES[str(selected_server_ip)])
                ethernet_reply.set_dst(arp_packet.hwsrc)
                ethernet_reply.set_payload(arp_reply)

                # Send the ARP reply
                event.connection.send(ethernet_reply)

                # Set flow rules for future traffic
                add_flow(event.connection, arp_packet.src_ip, selected_server_ip)

def add_flow(connection, src_ip, dst_ip):
    # Add flows to the switch for both directions: client to server and server to client
    match_client_to_server = of.ofp_match()
    match_client_to_server.nw_src = src_ip
    match_client_to_server.nw_dst = VIRTUAL_IP
    actions = [of.ofp_action_nw_addr.set_dst(dst_ip), of.ofp_action_output(port=event.port)]
    
    flow_mod_client_to_server = of.ofp_flow_mod()
    flow_mod_client_to_server.match = match_client_to_server
    flow_mod_client_to_server.actions = actions
    flow_mod_client_to_server.idle_timeout = 10
    flow_mod_client_to_server.hard_timeout = 30
    connection.send(flow_mod_client_to_server)

    match_server_to_client = of.ofp_match()
    match_server_to_client.nw_src = dst_ip
    match_server_to_client.nw_dst = src_ip
    actions = [of.ofp_action_nw_addr.set_dst(VIRTUAL_IP), of.ofp_action_output(port=event.port)]
    
    flow_mod_server_to_client = of.ofp_flow_mod()
    flow_mod_server_to_client.match = match_server_to_client
    flow_mod_server_to_client.actions = actions
    flow_mod_server_to_client.idle_timeout = 10
    flow_mod_server_to_client.hard_timeout = 30
    connection.send(flow_mod_server_to_client)

def handle_icmp_request(event):
    packet = event.parsed
    if packet.type == ethernet.IP_TYPE and packet.payload.protocol == icmp.ICMP_TYPE:
        icmp_packet = packet.payload
        if isinstance(icmp_packet, icmp.echo):
            log.debug("Handling ICMP echo request from %s", packet.payload.srcip)
            # Just forward the ICMP request to the server based on existing flow rules
            # The reverse flow will handle the reply automatically

def _handle_packet_in(event):
    packet = event.parsed

    if packet.type == ethernet.ARP_TYPE:
        handle_arp_request(event)
    elif packet.type == ethernet.IP_TYPE:
        handle_icmp_request(event)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_packet_in)
    log.info("Virtual IP Load Balancing switch running...")

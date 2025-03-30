# # Virtual IP Load Balancing Switch for POX
# from pox.core import core
# from pox.lib.packet import arp, icmp, ethernet
# from pox.lib.addresses import IPAddr, EthAddr
# from pox.openflow import libopenflow_01 as of

# import random

# log = core.getLogger()

# # Virtual IP and Real IP addresses of servers
# VIRTUAL_IP = IPAddr("10.0.0.10")
# SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # Real IPs of servers h5 and h6
# MAC_ADDRESSES = {  # MAC addresses corresponding to the servers
#     "10.0.0.5": EthAddr("00:00:00:00:00:05"),
#     "10.0.0.6": EthAddr("00:00:00:00:00:06"),
# }

# # Round-robin index for selecting a server
# server_index = 0

# # Dictionary to track client IPs and their assigned server IPs
# client_server_mapping = {}


# def handle_arp_request(event):
#     global server_index

#     # Parse the ARP request
#     packet = event.parsed
#     if packet.type == ethernet.ARP_TYPE:
#         arp_packet = packet.payload
#         if arp_packet.opcode == arp.REQUEST:
#             # If the request is for our virtual IP
#             if arp_packet.protodst == VIRTUAL_IP:
#                 client_ip = arp_packet.protosrc

#                 # Check if this client already has an assigned server
#                 if client_ip in client_server_mapping:
#                     selected_server_ip = client_server_mapping[client_ip]
#                     log.info(f"Client {client_ip} already assigned to server {selected_server_ip}.")
#                 else:
#                     # Select the next server in round-robin fashion
#                     selected_server_ip = SERVER_IPS[server_index]
#                     server_index = (server_index + 1) % len(SERVER_IPS)

#                     # Assign the selected server to the client
#                     client_server_mapping[client_ip] = selected_server_ip
#                     log.info(f"New client {client_ip} assigned to server {selected_server_ip}.")

#                 # Create ARP reply
#                 arp_reply = arp()
#                 arp_reply.hwsrc = MAC_ADDRESSES[str(selected_server_ip)]
#                 arp_reply.hwdst = arp_packet.hwsrc
#                 arp_reply.opcode = arp.REPLY
#                 arp_reply.protosrc = selected_server_ip
#                 arp_reply.protodst = arp_packet.protosrc

#                 # Create Ethernet frame
#                 ethernet_reply = ethernet()
#                 ethernet_reply.src = MAC_ADDRESSES[str(selected_server_ip)]
#                 ethernet_reply.dst = arp_packet.hwsrc
#                 ethernet_reply.payload = arp_reply

#                 # Create the OpenFlow PacketOut message
#                 packet_out = of.ofp_packet_out()
#                 packet_out.data = ethernet_reply.pack()  # Pack the Ethernet frame into raw data
#                 # packet_out.in_port = event.port  # The port from which the packet came
#                 packet_out.actions.append(of.ofp_action_output(port=event.port))  # Action to send it back out on the same port

#                 # Send the OpenFlow PacketOut message
#                 event.connection.send(packet_out)

#                 # Set flow rules for future traffic
#                 add_flow(event, arp_packet.protosrc, selected_server_ip)
#             # Handle ARP requests from servers to clients
#             else: 
#                 # client_mac = MAC_ADDRESSES[str(arp_packet.protodst)]
#                 client_mac = arp_packet.hwdst

#                 # Send ARP reply with client's MAC
#                 reply = arp()
#                 reply.hwsrc = client_mac
#                 reply.hwdst = arp_packet.hwsrc
#                 reply.opcode = arp.REPLY
#                 reply.protosrc = arp_packet.protodst
#                 reply.protodst = arp_packet.protosrc
                
#                 eth = ethernet()
#                 eth.src = client_mac
#                 eth.dst = arp_packet.hwsrc
#                 eth.type = ethernet.ARP_TYPE
#                 eth.payload = reply
                
#                 packet_out = of.ofp_packet_out()
#                 packet_out.data = eth.pack()
#                 packet_out.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
#                 packet_out.in_port = event.port
#                 event.connection.send(packet_out)
#                 log.info(f"Replied to server ARP for client {arp_packet.protodst}")


# def _handle_packet_in(event):
#     packet = event.parsed

#     if packet.type == ethernet.ARP_TYPE:
#         handle_arp_request(event)

# def launch():
#     core.openflow.addListenerByName("PacketIn", _handle_packet_in)
#     log.info("Virtual IP Load Balancing switch running...")


# def parsePortFromIP(client_IP):
#     # Split the IP address by periods ('.') to get each part
#     ip_parts = str(client_IP).split('.')
    
#     # Get the last part of the IP (which corresponds to the port number)
#     last_part = ip_parts[-1]
    
#     # Return the integer value of the last part, which represents the port number
#     return int(last_part)

# # TO-DO: Rename to "add_flow"
# def add_flow(event, client_IP, real_server_ip):
#     """
#     Install the flow rule dynamically based on the client IP and selected real server IP
#     """

#     client_in_port = parsePortFromIP(client_IP)
#     server_in_port = parsePortFromIP(real_server_ip)

#     # Flow rule for client to real server
#     msg = of.ofp_flow_mod()
#     msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
#     msg.match.in_port = client_in_port  
#     msg.match.nw_dst = VIRTUAL_IP
#     msg.actions.append(of.ofp_action_nw_addr.set_dst(real_server_ip)) 
#     msg.actions.append(of.ofp_action_output(port=server_in_port))  
#     event.connection.send(msg)

#     # Flow rule for server to client (reverse direction)
#     msg = of.ofp_flow_mod()
#     msg.match.dl_type = 0x800 
#     msg.match.in_port = server_in_port  
#     msg.match.nw_dst = client_IP  
#     msg.match.nw_src = real_server_ip
#     msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))  
#     msg.actions.append(of.ofp_action_output(port=client_in_port))  
#     event.connection.send(msg)
    












from pox.core import core
from pox.lib.packet import arp, ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.openflow import libopenflow_01 as of

log = core.getLogger()

# Virtual IP and Real IP addresses of servers
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # Real IPs of servers
CLIENT_IPS = [IPAddr("10.0.0.1"), IPAddr("10.0.0.2"), IPAddr("10.0.0.3"), IPAddr("10.0.0.4")]

# Predefined MAC addresses for all hosts
MAC_ADDRESSES = {
    "10.0.0.1": EthAddr("00:00:00:00:00:01"),
    "10.0.0.2": EthAddr("00:00:00:00:00:02"),
    "10.0.0.3": EthAddr("00:00:00:00:00:03"),
    "10.0.0.4": EthAddr("00:00:00:00:00:04"),
    "10.0.0.5": EthAddr("00:00:00:00:00:05"),
    "10.0.0.6": EthAddr("00:00:00:00:00:06"),
}

server_index = 0  # Round-robin index

def parsePortFromIP(ip):
    return int(str(ip).split('.')[-1])

def install_flow_rule(event, client_IP, real_server_ip):
    client_in_port = parsePortFromIP(client_IP)
    server_in_port = parsePortFromIP(real_server_ip)

    # Client -> Server rule
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800  # IPv4
    msg.match.in_port = client_in_port
    msg.match.nw_dst = VIRTUAL_IP
    msg.actions.append(of.ofp_action_nw_addr.set_dst(real_server_ip))
    msg.actions.append(of.ofp_action_output(port=server_in_port))
    event.connection.send(msg)

    # Server -> Client rule
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800
    msg.match.in_port = server_in_port
    msg.match.nw_src = real_server_ip
    msg.match.nw_dst = client_IP
    msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
    msg.actions.append(of.ofp_action_output(port=client_in_port))
    event.connection.send(msg)

    log.info(f"Installed flow rules for {client_IP} <-> {real_server_ip}")

def handle_arp_request(event, arp_packet):
    global server_index

    # Handle ARP requests for virtual IP
    if arp_packet.protodst == VIRTUAL_IP:
        selected_server_ip = SERVER_IPS[server_index]
        server_index = (server_index + 1) % len(SERVER_IPS)
        server_mac = MAC_ADDRESSES[str(selected_server_ip)]
        
        # Send ARP reply with server's MAC
        reply = arp()
        reply.hwsrc = server_mac
        reply.hwdst = arp_packet.hwsrc
        reply.opcode = arp.REPLY
        reply.protosrc = VIRTUAL_IP  # Key change: Use virtual IP as source
        reply.protodst = arp_packet.protosrc
        
        eth = ethernet()
        eth.src = server_mac
        eth.dst = arp_packet.hwsrc
        eth.type = ethernet.ARP_TYPE
        eth.payload = reply
        
        # Send packet
        packet_out = of.ofp_packet_out()
        packet_out.data = eth.pack()
        packet_out.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        packet_out.in_port = event.port
        event.connection.send(packet_out)
        
        install_flow_rule(event, arp_packet.protosrc, selected_server_ip)
        log.info(f"Replied to ARP for VIP with {selected_server_ip}")

    # Handle ARP requests from servers to clients
    elif str(arp_packet.protosrc) in [str(ip) for ip in SERVER_IPS] and str(arp_packet.protodst) in [str(ip) for ip in CLIENT_IPS]:
        client_mac = MAC_ADDRESSES[str(arp_packet.protodst)]
        
        # Send ARP reply with client's MAC
        reply = arp()
        reply.hwsrc = client_mac
        reply.hwdst = arp_packet.hwsrc
        reply.opcode = arp.REPLY
        reply.protosrc = arp_packet.protodst
        reply.protodst = arp_packet.protosrc
        
        eth = ethernet()
        eth.src = client_mac
        eth.dst = arp_packet.hwsrc
        eth.type = ethernet.ARP_TYPE
        eth.payload = reply
        
        packet_out = of.ofp_packet_out()
        packet_out.data = eth.pack()
        packet_out.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        packet_out.in_port = event.port
        event.connection.send(packet_out)
        log.info(f"Replied to server ARP for client {arp_packet.protodst}")

def _handle_packet_in(event):
    packet = event.parsed
    if not packet.parsed:
        return

    if packet.type == ethernet.ARP_TYPE:
        arp_packet = packet.payload
        if arp_packet.opcode == arp.REQUEST:
            handle_arp_request(event, arp_packet)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_packet_in)
    log.info("Virtual IP Load Balancer running...")
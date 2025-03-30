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

# def add_flow(event, client_IP, real_server_ip):
#     """
#     Install the flow rule dynamically based on the client IP and selected real server IP
#     """

#     client_in_port = parsePortFromIP(client_IP)
#     server_in_port = parsePortFromIP(real_server_ip)

    # # Flow rule for client to real server
    # msg = of.ofp_flow_mod()
    # msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
    # msg.match.in_port = client_in_port  
    # msg.match.nw_dst = VIRTUAL_IP
    # msg.actions.append(of.ofp_action_nw_addr.set_dst(real_server_ip)) 
    # msg.actions.append(of.ofp_action_output(port=server_in_port))  
    # event.connection.send(msg)

    # # Flow rule for server to client (reverse direction)
    # msg = of.ofp_flow_mod()
    # msg.match.dl_type = 0x800 
    # msg.match.in_port = server_in_port  
    # msg.match.nw_dst = client_IP  
    # msg.match.nw_src = real_server_ip
    # msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))  
    # msg.actions.append(of.ofp_action_output(port=client_in_port))  
    # event.connection.send(msg)
    











from pox.core import core
from pox.lib.packet import arp, ethernet, ipv4, icmp
from pox.lib.addresses import IPAddr, EthAddr
from pox.openflow import libopenflow_01 as of

log = core.getLogger()

VIRTUAL_IP = IPAddr("10.0.0.10")
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
CLIENT_IPS = [IPAddr("10.0.0.1"), IPAddr("10.0.0.2"), IPAddr("10.0.0.3"), IPAddr("10.0.0.4")]

MAC_ADDRESSES = {
    "10.0.0.1": EthAddr("00:00:00:00:00:01"),
    "10.0.0.2": EthAddr("00:00:00:00:00:02"),
    "10.0.0.3": EthAddr("00:00:00:00:00:03"),
    "10.0.0.4": EthAddr("00:00:00:00:00:04"),
    "10.0.0.5": EthAddr("00:00:00:00:00:05"),
    "10.0.0.6": EthAddr("00:00:00:00:00:06"),
}

server_index = 0
client_server_map = {}  # Maps client IP to server IP


def parse_port_from_ip(client_IP):
    # Split the IP address by periods ('.') to get each part
    ip_parts = str(client_IP).split('.')
    
    # Get the last part of the IP (which corresponds to the port number)
    last_part = ip_parts[-1]
    
    # Return the integer value of the last part, which represents the port number
    return int(last_part)

def add_flow(connection, client_ip, real_server_ip):
    """
    Install the flow rule dynamically based on the client IP and selected real server IP
    """

    client_in_port = parse_port_from_ip(client_ip)
    server_in_port = parse_port_from_ip(real_server_ip)

    # Flow rule for client to real server
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
    msg.match.in_port = client_in_port  
    msg.match.nw_dst = VIRTUAL_IP
    msg.actions.append(of.ofp_action_nw_addr.set_dst(real_server_ip)) 
    msg.actions.append(of.ofp_action_output(port=server_in_port))  
    connection.send(msg)

    # Flow rule for server to client (reverse direction)
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800 
    msg.match.in_port = server_in_port  
    msg.match.nw_dst = client_ip  
    msg.match.nw_src = real_server_ip
    msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))  
    msg.actions.append(of.ofp_action_output(port=client_in_port))  
    connection.send(msg)
    

def handle_arp(event, arp_pkt):
    global server_index

    if arp_pkt.protodst == VIRTUAL_IP:
        # Client ARP for VIP
        client_ip = arp_pkt.protosrc
        
        #  Check if this client already has an assigned server
        if client_ip in client_server_map:
            server_ip = client_server_map[client_ip]
        else:
            # Select the next server in round-robin fashion
            server_ip = SERVER_IPS[server_index]
            server_index = (server_index + 1) % len(SERVER_IPS)

            # Assign the selected server to the client
            client_server_map[client_ip] = server_ip

        # Send ARP reply with server's MAC
        arp_reply = arp(
            opcode=arp.REPLY,
            hwsrc=MAC_ADDRESSES[str(server_ip)],
            hwdst=arp_pkt.hwsrc,
            protosrc=VIRTUAL_IP,
            protodst=client_ip
        )
        eth = ethernet(
            src=MAC_ADDRESSES[str(server_ip)],
            dst=arp_pkt.hwsrc,
            type=ethernet.ARP_TYPE
        )
        eth.payload = arp_reply
        add_flow(event.connection, client_ip, server_ip)
        send_packet(event, eth)

    elif str(arp_pkt.protosrc) in [str(ip) for ip in SERVER_IPS]:
        # Server ARP for client
        client_ip = arp_pkt.protodst
        arp_reply = arp(
            opcode=arp.REPLY,
            hwsrc=MAC_ADDRESSES[str(client_ip)],
            hwdst=arp_pkt.hwsrc,
            protosrc=client_ip,
            protodst=arp_pkt.protosrc
        )
        eth = ethernet(
            src=MAC_ADDRESSES[str(client_ip)],
            dst=arp_pkt.hwsrc,
            type=ethernet.ARP_TYPE
        )
        eth.payload = arp_reply
        send_packet(event, eth)

def handle_ip(event, ip_pkt):
    if ip_pkt.dstip == VIRTUAL_IP:
        # Packet to VIP: Use mapped server
        client_ip = ip_pkt.srcip
        server_ip = client_server_map.get(client_ip)
        
        if server_ip:
            # Modify destination IP and forward
            ip_pkt.dstip = server_ip
            ip_pkt.payload.checksum = None  # Force recalculation
            server_port = parse_port_from_ip(server_ip)
            
            # Send modified packet
            msg = of.ofp_packet_out()
            msg.data = event.ofp.pack()
            msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
            msg.actions.append(of.ofp_action_output(port=server_port))
            event.connection.send(msg)

def send_packet(event, packet):
    msg = of.ofp_packet_out()
    msg.data = packet.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    msg.in_port = event.port
    event.connection.send(msg)

def _handle_packet_in(event):
    packet = event.parsed
    if not packet.parsed:
        return

    if packet.type == ethernet.ARP_TYPE:
        arp_pkt = packet.payload
        if arp_pkt.opcode == arp.REQUEST:
            handle_arp(event, arp_pkt)
    elif packet.type == ethernet.IP_TYPE:
        ip_pkt = packet.payload
        handle_ip(event, ip_pkt)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_packet_in)
    log.info("Load balancer running.")
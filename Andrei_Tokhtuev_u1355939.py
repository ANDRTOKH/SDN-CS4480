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

# Dictionary to track client IPs and their assigned server IPs
client_server_mapping = {}


def handle_arp_request(event):
    global server_index

    # Parse the ARP request
    packet = event.parsed
    if packet.type == ethernet.ARP_TYPE:
        arp_packet = packet.payload
        if arp_packet.opcode == arp.REQUEST:
            # If the request is for our virtual IP
            if arp_packet.protodst == VIRTUAL_IP:
                client_ip = arp_packet.protosrc

                # Check if this client already has an assigned server
                if client_ip in client_server_mapping:
                    selected_server_ip = client_server_mapping[client_ip]
                    log.info(f"Client {client_ip} already assigned to server {selected_server_ip}.")
                else:
                    # Select the next server in round-robin fashion
                    selected_server_ip = SERVER_IPS[server_index]
                    server_index = (server_index + 1) % len(SERVER_IPS)

                    # Assign the selected server to the client
                    client_server_mapping[client_ip] = selected_server_ip
                    log.info(f"New client {client_ip} assigned to server {selected_server_ip}.")

                # Create ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = MAC_ADDRESSES[str(selected_server_ip)]
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = selected_server_ip
                arp_reply.protodst = arp_packet.protosrc

                # Create Ethernet frame
                ethernet_reply = ethernet()
                ethernet_reply.src = MAC_ADDRESSES[str(selected_server_ip)]
                ethernet_reply.dst = arp_packet.hwsrc
                ethernet_reply.payload = arp_reply

                # Create the OpenFlow PacketOut message
                packet_out = of.ofp_packet_out()
                packet_out.data = ethernet_reply.pack()  # Pack the Ethernet frame into raw data
                # packet_out.in_port = event.port  # The port from which the packet came
                packet_out.actions.append(of.ofp_action_output(port=event.port))  # Action to send it back out on the same port

                # Send the OpenFlow PacketOut message
                event.connection.send(packet_out)

                # Set flow rules for future traffic
                # add_flow(event.connection, arp_packet.protosrc, selected_server_ip, event.port)
                install_flow_rule(event, arp_packet.protosrc, selected_server_ip)
            # Handle ARP requests from servers to clients
            else: 
                # client_mac = MAC_ADDRESSES[str(arp_packet.protodst)]
                client_mac = arp_packet.hwdst

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



def add_flow(connection, src_ip, dst_ip, in_port):
    # Add flows to the switch for both directions: client to server and server to client
    match_client_to_server = of.ofp_match()
    match_client_to_server.dl_type = 0x0800  # Match IP packets (EtherType for IPv4 is 0x0800)
    match_client_to_server.nw_src = src_ip
    match_client_to_server.nw_dst = VIRTUAL_IP
    actions = [of.ofp_action_nw_addr.set_dst(dst_ip), of.ofp_action_output(port=in_port)]
    
    flow_mod_client_to_server = of.ofp_flow_mod()
    flow_mod_client_to_server.match = match_client_to_server
    flow_mod_client_to_server.actions = actions
    flow_mod_client_to_server.idle_timeout = 10
    flow_mod_client_to_server.hard_timeout = 30
    connection.send(flow_mod_client_to_server)

    match_server_to_client = of.ofp_match()
    match_server_to_client.dl_type = 0x0800  # Match IP packets (EtherType for IPv4 is 0x0800)
    match_server_to_client.nw_src = dst_ip
    match_server_to_client.nw_dst = src_ip
    actions = [of.ofp_action_nw_addr.set_dst(VIRTUAL_IP), of.ofp_action_output(port=in_port)]
    
    flow_mod_server_to_client = of.ofp_flow_mod()
    flow_mod_server_to_client.match = match_server_to_client
    flow_mod_server_to_client.actions = actions
    flow_mod_server_to_client.idle_timeout = 10
    flow_mod_server_to_client.hard_timeout = 30
    connection.send(flow_mod_server_to_client)


def _handle_packet_in(event):
    packet = event.parsed

    if packet.type == ethernet.ARP_TYPE:
        handle_arp_request(event)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_packet_in)
    log.info("Virtual IP Load Balancing switch running...")


def parsePortFromIP(client_IP):
    # Split the IP address by periods ('.') to get each part
    ip_parts = str(client_IP).split('.')
    
    # Get the last part of the IP (which corresponds to the port number)
    last_part = ip_parts[-1]
    
    # Return the integer value of the last part, which represents the port number
    return int(last_part)

# TO-DO: Rename to "add_flow"
def install_flow_rule(event, client_IP, real_server_ip):
    """
    Install the flow rule dynamically based on the client IP and selected real server IP
    """

    client_in_port = parsePortFromIP(client_IP)
    server_in_port = parsePortFromIP(real_server_ip)

    # Flow rule for client to real server
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
    msg.match.in_port = client_in_port  
    msg.match.nw_dst = VIRTUAL_IP
    msg.actions.append(of.ofp_action_nw_addr.set_dst(real_server_ip)) 
    msg.actions.append(of.ofp_action_output(port=server_in_port))  
    event.connection.send(msg)

    # Flow rule for server to client (reverse direction)
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800 
    msg.match.in_port = server_in_port  
    msg.match.nw_dst = client_IP  
    msg.match.nw_src = real_server_ip
    msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))  
    msg.actions.append(of.ofp_action_output(port=client_in_port))  
    event.connection.send(msg)
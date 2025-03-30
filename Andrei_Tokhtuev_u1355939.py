from pox.core import core
from pox.lib.packet import arp, ethernet, ipv4, icmp
from pox.lib.addresses import IPAddr, EthAddr
from pox.openflow import libopenflow_01 as of

log = core.getLogger()

# Round-robin index for selecting a server
server_index = 0

# Dictionary to track client IPs and their assigned server IPs
client_server_map = {}

# Mapping of IP addresses to MAC addresses
MAC_ADDRESSES = {
    "10.0.0.1": EthAddr("00:00:00:00:00:01"),
    "10.0.0.2": EthAddr("00:00:00:00:00:02"),
    "10.0.0.3": EthAddr("00:00:00:00:00:03"),
    "10.0.0.4": EthAddr("00:00:00:00:00:04"),
    "10.0.0.5": EthAddr("00:00:00:00:00:05"),
    "10.0.0.6": EthAddr("00:00:00:00:00:06"),
}

# Virtual IP address used by clients to connect to the service
VIRTUAL_IP = IPAddr("10.0.0.10")

# List of available server IP addresses
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]

# List of client IP addresses
CLIENT_IPS = [IPAddr("10.0.0.1"), IPAddr("10.0.0.2"), IPAddr("10.0.0.3"), IPAddr("10.0.0.4")]

def parse_port_from_ip(client_IP):
    """
    Extract the port number from a client's IP address by using the last octet of the IP.
    For example, the IP '10.0.0.1' results in port '1'.

    Args:
    - client_IP: The IP address of the client.

    Returns:
    - port: The port number corresponding to the last octet of the IP.
    """
    ip_parts = str(client_IP).split('.')
    last_part = ip_parts[-1]
    return int(last_part)

def add_flow(connection, client_ip, real_server_ip):
    """
    Install flow entries on the switch to forward traffic between the client and the server.
    Two flows are installed:
    - One for packets from the client to the server.
    - One for packets from the server to the client (reverse flow).
    
    Args:
    - connection: The OpenFlow connection to the switch.
    - client_ip: The IP address of the client.
    - real_server_ip: The real server IP to forward traffic to.
    """
    client_in_port = parse_port_from_ip(client_ip)
    server_in_port = parse_port_from_ip(real_server_ip)

    # Flow rule for client to real server
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800  # Match IPv4 packets
    msg.match.in_port = client_in_port
    msg.match.nw_dst = VIRTUAL_IP  # Match traffic destined for the virtual IP
    msg.actions.append(of.ofp_action_nw_addr.set_dst(real_server_ip))  # Modify destination IP to real server IP
    msg.actions.append(of.ofp_action_output(port=server_in_port))  # Forward packet to the server's port
    connection.send(msg)

    # Flow rule for server to client (reverse direction)
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800  # Match IPv4 packets
    msg.match.in_port = server_in_port
    msg.match.nw_dst = client_ip  # Match traffic destined for the client
    msg.match.nw_src = real_server_ip  # Match traffic coming from the real server
    msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))  # Modify source IP to virtual IP
    msg.actions.append(of.ofp_action_output(port=client_in_port))  # Forward packet to the client's port
    connection.send(msg)

def handle_arp_request(event, arp_pkt):
    """
    Handle incoming ARP requests. If the ARP request is for the virtual IP, the switch sends 
    an ARP reply with the MAC address of the assigned server.
    
    Args:
    - event: The incoming packet event from OpenFlow.
    - arp_pkt: The ARP request packet.
    """
    global server_index

    if arp_pkt.protodst == VIRTUAL_IP:  # ARP request for virtual IP
        client_ip = arp_pkt.protosrc

        # Check if this client already has an assigned server
        if client_ip in client_server_map:
            server_ip = client_server_map[client_ip]
        else:
            # Select the next server in round-robin fashion
            server_ip = SERVER_IPS[server_index]
            server_index = (server_index + 1) % len(SERVER_IPS)

            # Assign the selected server to the client
            client_server_map[client_ip] = server_ip

        # Create an ARP reply to send to the client
        arp_reply = arp(
            opcode=arp.REPLY,
            hwdst=arp_pkt.hwsrc,
            hwsrc=MAC_ADDRESSES[str(server_ip)],
            protodst=client_ip,
            protosrc=VIRTUAL_IP
        )
        e = ethernet(
            src=MAC_ADDRESSES[str(server_ip)],
            type=ethernet.ARP_TYPE,
            dst=arp_pkt.hwsrc  # The original sender of the ARP request
        )
        e.payload = arp_reply
        
        # Add flow for client-server communication
        add_flow(event.connection, client_ip, server_ip)
        
        # Send the ARP reply to the client
        send_packet(event, e)

    elif str(arp_pkt.protosrc) in [str(ip) for ip in SERVER_IPS]:  # ARP request from server to client
        client_ip = arp_pkt.protodst
        arp_reply = arp(
            opcode=arp.REPLY,
            hwsrc=MAC_ADDRESSES[str(client_ip)],
            hwdst=arp_pkt.hwsrc,
            protosrc=client_ip,
            protodst=arp_pkt.protosrc
        )
        e = ethernet(
            src=MAC_ADDRESSES[str(client_ip)],
            dst=arp_pkt.hwsrc,
            type=ethernet.ARP_TYPE
        )
        e.payload = arp_reply
        send_packet(event, e)

def handle_ip_request(event, ip_pkt):
    """
    Handle incoming IP packets. If the destination IP matches the virtual IP, 
    the switch forwards the packet to the appropriate server.
    
    Args:
    - event: The incoming packet event from OpenFlow.
    - ip_pkt: The IP packet.
    """
    if ip_pkt.dstip == VIRTUAL_IP:
        client_ip = ip_pkt.srcip
        server_ip = client_server_map.get(client_ip)

        if server_ip:
            # Modify the destination IP to the real server IP
            ip_pkt.dstip = server_ip
            ip_pkt.payload.checksum = None  # Clear checksum to force recalculation
            server_port = parse_port_from_ip(server_ip)

            # Create a packet-out message to forward the packet to the server
            msg = of.ofp_packet_out()
            msg.data = event.ofp.pack()
            msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))  # Modify destination IP
            msg.actions.append(of.ofp_action_output(port=server_port))  # Forward packet to server's port
            event.connection.send(msg)

def send_packet(event, packet):
    """
    Send a packet to the OpenFlow switch for further processing or forwarding.
    
    Args:
    - event: The incoming packet event from OpenFlow.
    - packet: The packet to send.
    """
    msg = of.ofp_packet_out()
    msg.data = packet.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))  # Output on the incoming port
    msg.in_port = event.port
    event.connection.send(msg)

def _handle_packet_in(event):
    """
    Handle incoming packets and process based on their type (ARP or IP).
    
    Args:
    - event: The incoming packet event from OpenFlow.
    """
    packet = event.parsed
    if not packet.parsed:
        return

    # Handle ARP packets
    if packet.type == ethernet.ARP_TYPE:
        arp_pkt = packet.payload
        if arp_pkt.opcode == arp.REQUEST:  # Only handle ARP requests
            handle_arp_request(event, arp_pkt)

    # Handle IP packets
    elif packet.type == ethernet.IP_TYPE:
        ip_pkt = packet.payload
        handle_ip_request(event, ip_pkt)

def launch():
    """
    Initialize the load balancer and set up a listener for incoming packets.
    """
    core.openflow.addListenerByName("PacketIn", _handle_packet_in)
    log.info("Load balancer running.")

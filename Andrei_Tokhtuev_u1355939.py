# Copyright 2013 <Your Name Here>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A skeleton POX component

You can customize this to do whatever you like.  Don't forget to
adjust the Copyright above, and to delete the Apache license if you
don't want to release under Apache (but consider doing so!).

Rename this file to whatever you like, .e.g., mycomponent.py.  You can
then invoke it with "./pox.py mycomponent" if you leave it in the
ext/ directory.

Implement a launch() function (as shown below) which accepts commandline
arguments and starts off your component (e.g., by listening to events).

Edit this docstring and your launch function's docstring.  These will
show up when used with the help component ("./pox.py help --mycomponent").
"""

# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

# Create a logger for this component
log = core.getLogger()

# Mapping between virtual IP and real IP
SERVER_VIRTUAL_IP = IPAddr("10.0.0.10")
REAL_SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # List of real server IPs
REAL_SERVER_MACS = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]  # Corresponding MACs

# Round-robin state (a simple counter to alternate between servers)
round_robin_index = 0

@poxutil.eval_args

def launch():
    """
    Launch the POX component, listen to switches, and handle ARP requests and ICMP traffic.
    """
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("POX controller running with ARP interception and virtual IP mapping.")
  # When your component is specified on the commandline, POX automatically
  # calls this function.

# Event handler for when a switch connects
def _handle_ConnectionUp(event):
    log.info(f"Switch {event.dpid} has connected")


def _handle_PacketIn(event):
    packet = event.parsed

    if packet.type == pkt.ethernet.ARP_TYPE:
        arp = packet.payload
        if arp.opcode == pkt.arp.REQUEST and arp.protodst == SERVER_VIRTUAL_IP:
            log.info(f"Intercepted ARP request for {SERVER_VIRTUAL_IP}.")

            # Pick the next server for the client using round-robin
            client_IP = arp.protosrc
            real_server_ip, server_mac = get_next_server_ip_and_mac()

            # Send an ARP reply for the virtual IP (10.0.0.10)
            arp_reply = pkt.arp.ARP()
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.hwsrc = server_mac  # Virtual MAC
            arp_reply.hwdst = arp.hwsrc   # Client's MAC
            arp_reply.protosrc = SERVER_VIRTUAL_IP # Virtual IP
            arp_reply.protodst = arp.protosrc      # Client's IP

            # Install the flow rule for the client -> server mapping
            install_flow_rule(event, client_IP, real_server_ip)

            # Construct the Ethernet frame
            ether = pkt.ethernet()
            ether.type = pkt.ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = server_mac
            ether.payload = arp_reply

            # Send ARP reply
            event.connection.send(ether.pack()) #??? 
            log.info(f"Sent ARP reply for {SERVER_VIRTUAL_IP}.")

def install_flow_rule(event, client_IP, real_server_ip):
    """
    Install the flow rule dynamically based on the client IP and selected real server IP
    """

    client_in_port = parsePortFromIP(client_IP)
    server_in_port = parsePortFromIP(real_server_ip)

    ## Template 
    # msg = of.ofp_flow_mod()
    # msg.match.in_port = # Switch port number the packet arrived on
    # msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
    # msg.match.nw_dst = # IP destination address
    # msg.match.nw_src = # IP source address (only in the server to client message handler)
    # msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip)) # Rule

    # Flow rule for client to real server
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
    msg.match.in_port = client_in_port  # Client port 
    msg.match.nw_dst = SERVER_VIRTUAL_IP
    msg.actions.append(of.ofp_action_set_field(field=of.ofp_match.nw_dst(real_server_ip)))  # Redirect to real server
    msg.actions.append(of.ofp_action_output(port=server_in_port))  # Forward to server port 
    event.connection.send(msg)
    log.info(f"Installed flow rule for client -> server: {client_IP} -> {real_server_ip}")

    # Flow rule for server to client (reverse direction)
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x800 # Ethertype / length (e.g. 0x0800 = IPv4)
    msg.match.in_port = server_in_port  # Server port 
    msg.match.nw_dst = client_IP  # h1's IP
    msg.match.nw_src = real_server_ip
    msg.actions.append(of.ofp_action_set_field(field=of.ofp_match.nw_src(SERVER_VIRTUAL_IP)))  # Rewrite src IP to virtual IP
    msg.actions.append(of.ofp_action_output(port=client_in_port))  # Send back to client 
    event.connection.send(msg)
    log.info(f"Installed flow rule for server -> client: {real_server_ip} -> {client_IP}")

  # Store previous state so that round-robin works correctly
def get_next_server_ip_and_mac():
    global round_robin_index
    # Get the current server IP and MAC using round-robin
    server_ip = REAL_SERVER_IPS[round_robin_index]
    server_mac = REAL_SERVER_MACS[round_robin_index]
    round_robin_index = (round_robin_index + 1) % len(REAL_SERVER_IPS)  # Cycle through the servers
    return server_ip, server_mac

def parsePortFromIP(client_IP):
    # Split the IP address by periods ('.') to get each part
    ip_parts = client_IP.split('.')
    
    # Get the last part of the IP (which corresponds to the port number)
    last_part = ip_parts[-1]
    
    # Return the integer value of the last part, which represents the port number
    return int(last_part)

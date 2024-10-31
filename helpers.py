import wrapper
import struct
from wrapper import send_to_link

BROADCAST = "ff:ff:ff:ff:ff:ff"
MULTICAST = "01:80:c2:00:00:00"
MULTICAST_BYTES = bytes.fromhex("0180C2000000")

class BPDU:
    def __init__(self, src_mac, root_bridge_ID, root_path_cost, 
                 sender_bridge_ID, interface, message_age):
        self.dst_mac = MULTICAST_BYTES
        self.src_mac = src_mac
        self.llc_length = 0x0026
        self.dsap = 0x42
        self.ssap = 0x42
        self.control = 0x03
        self.padding = 0x00000000
        self.flags = 0x00
        self.root_bridge_ID = root_bridge_ID
        self.root_path_cost = root_path_cost
        self.sender_bridge_ID = sender_bridge_ID
        self.port_ID = interface
        self.message_age = message_age
        self.max_age = 0x0014
        self.hello_time = 0x0002
        self.forward_delay = 0x000F

    def len(self): return 52

    def pack(self):
        pack = struct.pack('!6s6sHBBBIBQIQHHHHH', 
                           self.dst_mac, self.src_mac, self.llc_length, self.dsap, 
                           self.ssap, self.control, self.padding, self.flags, 
                           self.root_bridge_ID, self.root_path_cost, self.sender_bridge_ID, 
                           self.port_ID, self.message_age, self.max_age, self.hello_time, 
                           self.forward_delay)
        return pack

def stp_init(vlan_table, own_bridge_ID):
    # Init all switches as root
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    root_port = -1
 
    trunk_interfaces = dict()

    for i in vlan_table:
        if vlan_table[i] == 'T':
            trunk_interfaces[i] = "Designated"

    return trunk_interfaces, [root_bridge_ID, root_path_cost, root_port]

def unpack_buff(data):
    src_mac = data[6:12]
    root_bridge_ID = int.from_bytes(data[22:30], 'big')
    root_path_cost = int.from_bytes(data[30:34], 'big')
    bridge_ID =int.from_bytes(data[34:42], 'big')
    interface = int.from_bytes(data[42:44], 'big')
    message_age = int.from_bytes(data[44:46], 'big')

    bpdu = BPDU(src_mac, root_bridge_ID, root_path_cost,
                bridge_ID, interface, message_age)
    
    return bpdu

def config_switch(switch_id, interfaces):
    vlan_table = dict()

    f = open("configs/switch{}.cfg".format(switch_id), "r")

    # Read switch priority
    switch_prio_value = int(f.readline().strip())

    # Read VLAN configs
    lines = f.readlines()
    for line in lines:
        config = line.strip().split(" ")
        for i in interfaces:
            if config[0] == wrapper.get_interface_name(i):
                vlan_table[i] = config[1]

    return vlan_table, switch_prio_value

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def handle_bdpu(data, root, interface, trunk_interfaces, src_mac_bytes,
                own_bridge_ID):
    # Unpack bpdu
    bpdu = unpack_buff(data)

    # Unpack current root values
    root_bridge_ID = root[0]
    root_path_cost = root[1]
    root_port_ID = root[2]

    # Updating root
    if (bpdu.root_bridge_ID < root_bridge_ID and 
        bpdu.message_age < bpdu.max_age):
        root_bridge_ID = bpdu.root_bridge_ID

        # Add 10 to cost (all links are 100 Mbps)
        root_path_cost = bpdu.root_path_cost + 10 

        # Update root port
        root_port_ID = interface

        for i in trunk_interfaces:
                if i != root_port_ID:
                    trunk_interfaces[i] = "Blocking"

        trunk_interfaces[root_port_ID] == "Designated"

        # Update and forward this BPDU to all other trunk ports
        for i in trunk_interfaces:
            if i != interface:
                fwd_bpdu = BPDU(src_mac_bytes, root_bridge_ID, root_path_cost,
                                own_bridge_ID, i, bpdu.message_age + 1)
                send_to_link(i, fwd_bpdu.len(), fwd_bpdu.pack())
    
    # Unchanged root
    elif (bpdu.root_bridge_ID == root_bridge_ID and 
            bpdu.message_age < bpdu.max_age):

        # Same port, better cost
        if (interface == root_port_ID and 
            bpdu.root_path_cost + 10 < root_path_cost):
            root_path_cost = bpdu.sender_path_cost + 10

        # Different port, better cost
        elif (interface != root_port_ID and 
                bpdu.root_path_cost > root_path_cost):
            trunk_interfaces[interface] = "Designated"

    # Block ports that send back switch's BPDU
    elif (bpdu.sender_bridge_ID == own_bridge_ID and 
            bpdu.message_age < bpdu.max_age):
        trunk_interfaces[interface] = "Blocking"

    if own_bridge_ID == root_bridge_ID:
        for i in trunk_interfaces:
            trunk_interfaces[i] = "Designated"

    # Update own info
    root[0] = root_bridge_ID
    root[1] = root_path_cost
    root[2] = root_port_ID

def send_frame(dest_mac, mac_table, vlan_table, vlan_id, 
               interface, interfaces, data, length, trunk_interfaces):
    # Forward from access or trunk port, depending on vlan_id
    # Access
    if vlan_id == -1:
        fwd_from_access(dest_mac, mac_table, vlan_table, interface,
                        interfaces, data, length, trunk_interfaces)

    # Trunk
    else:
        fwd_from_trunk(dest_mac, mac_table, vlan_table, vlan_id,
                       interface, interfaces, data, length, trunk_interfaces)

# Switch receives a frame from access and forwards it
def fwd_from_access(dest_mac, mac_table, vlan_table, interface,
                    interfaces, data, length, trunk_interfaces):
    # Unicast
    if dest_mac != BROADCAST:

        # Destination MAC is known
        if dest_mac in mac_table:

            # Calculate VLANs, frame with tag and destination interface
            vlan_src = vlan_table[interface]
            dest_interface = mac_table[dest_mac]
            vlan_dest = vlan_table[dest_interface]
            tagged_frame = data[0:12] + create_vlan_tag(int(vlan_src)) + data[12:]

            # Same VLAN, therefore send; header remains the same
            if vlan_src == vlan_dest:
                send_to_link(dest_interface, length, data)

            # Different VLAN (from access to trunk)
            # Modify header and send
            elif (vlan_dest == 'T' and 
                  trunk_interfaces[dest_interface] == "Designated"):
                send_to_link(dest_interface, len(tagged_frame), tagged_frame)

        # Destination MAC is unknown
        else:

            # Calculate src VLAN and frame with tag only
            vlan_src = vlan_table[interface]
            tagged_frame = data[0:12] + create_vlan_tag(int(vlan_src)) + data[12:]

            for i in interfaces:
                vlan_dest = vlan_table[i]

                # For same VLAN (access to access), just send
                if i != interface and vlan_src == vlan_dest:
                    send_to_link(i, length, data)

                # For trunk port, update frame and send
                elif (i != interface and vlan_dest == 'T' and 
                      trunk_interfaces[i] == "Designated"):
                    send_to_link(i, len(tagged_frame), tagged_frame)

    # Broadcast
    else:

        # Calculate VLANs, frame with tag and destination interface
        vlan_src = vlan_table[interface]
        tagged_frame = data[0:12] + create_vlan_tag(int(vlan_src)) + data[12:]

        for i in interfaces:
            vlan_dest = vlan_table[i]

            # For same VLAN (access to access), just send
            if i != interface and vlan_src == vlan_dest:
                send_to_link(i, length, data)

            # For trunk port, update frame and send
            elif (i != interface and vlan_dest == 'T' and 
                  trunk_interfaces[i] == "Designated"):
                send_to_link(i, len(tagged_frame), tagged_frame)

# Switch receives a frame from trunk and forwards it
def fwd_from_trunk(dest_mac, mac_table, vlan_table, vlan_id,
                   interface, interfaces, data, length, trunk_interfaces):
    # Unicast
    if dest_mac != BROADCAST:

        # Destination MAC is known
        if dest_mac in mac_table:

            # Calculate dest VLAN, original frame and destination interface
            dest_interface = mac_table[dest_mac]
            vlan_dest = vlan_table[dest_interface]
            original_frame = data[0:12] + data[16:]
            
            # Same VLAN (trunk to trunk), therefore send; header remains the same
            if (vlan_dest == 'T' and 
                trunk_interfaces[dest_interface] == "Designated"):
                send_to_link(dest_interface, length, data)

            # Different VLAN (from trunk to access)
            # Modify header and send
            elif vlan_dest == str(vlan_id):
                send_to_link(dest_interface, len(original_frame), original_frame)

        # Destination MAC is unknown
        else:

            # Calculate original frame
            original_frame = data[0:12] + data[16:]

            for i in interfaces:
                vlan_dest = vlan_table[i]

                # For same VLAN (trunk to trunk), just send
                if (i != interface and 
                    vlan_dest == 'T' and 
                    trunk_interfaces[i] == "Designated"):
                    send_to_link(i, length, data)

                # For access port, update frame and send
                elif i != interface and vlan_dest == str(vlan_id):
                    send_to_link(i, len(original_frame), original_frame)

    # Broadcast
    else:

        # Calculate VLAN and original frame only
        original_frame = data[0:12] + data[16:]

        for i in interfaces:
            vlan_dest = vlan_table[i]

            # For same VLAN (trunk to trunk), just send
            if (i != interface and 
                vlan_dest == 'T' and 
                trunk_interfaces[i] == "Designated"):
                send_to_link(i, length, data)

            # For access port, update frame and send
            elif i != interface and vlan_dest == str(vlan_id):
                send_to_link(i, len(original_frame), original_frame)
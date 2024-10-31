#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
from helpers import stp_init, config_switch, handle_bdpu, send_frame, MULTICAST, BPDU

ENABLE_PRINT = False

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def send_bdpu_every_sec(own_bridge_ID, root, vlan_table):
    while True:
        # Send BDPU every second if switch is root
        if own_bridge_ID == root[0]:
            for i in vlan_table:
                if vlan_table[i] == 'T':
                    message_age = 0x0001
                    bpdu = BPDU(get_switch_mac(), root[0], root[1],
                                own_bridge_ID, i, message_age)
                    send_to_link(i, bpdu.len(), bpdu.pack())

        time.sleep(1)

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    # Init necessary variables
    # Mac table, vlan table, STP variables
    mac_table = dict()
    vlan_table, own_bridge_ID = config_switch(switch_id, interfaces)
    trunk_interfaces, root = stp_init(vlan_table, own_bridge_ID)

    # ROOT[0] = root_bridge_ID
    # ROOT[1] = root_path_cost
    # ROOT[2] = root_port_ID

    # Create and start a new thread that deals with sending BPDU
    t = threading.Thread(target=send_bdpu_every_sec, args=(own_bridge_ID, root, vlan_table))
    t.start()

    while True:
        # Note that data is of type bytes([...])
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Keep byte options too
        dest_mac_bytes = dest_mac
        src_mac_bytes = src_mac

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        #  Update source MAC in MAC_table
        mac_table[src_mac] = interface

        if ENABLE_PRINT:
            print(f'Destination MAC: {dest_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # Check for BPDU
        if dest_mac == MULTICAST:
            handle_bdpu(data, root, interface, trunk_interfaces,
                        src_mac_bytes, own_bridge_ID)

        # Normal frame
        else:
            send_frame(dest_mac, mac_table, vlan_table, vlan_id, 
                       interface, interfaces, data, length, trunk_interfaces)

if __name__ == "__main__":
    main()

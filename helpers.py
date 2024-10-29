import wrapper

def config_switch(switch_id, interfaces):
    vlan_table = dict()

    f = open("configs/switch{}.cfg".format(switch_id), "r")

    # Read switch priority
    switch_prio = int(f.readline().strip())

    # Read VLAN configs
    lines = f.readlines()
    for line in lines:
        config = line.strip().split(" ")
        for i in interfaces:
            if config[0] == wrapper.get_interface_name(i):
                vlan_table[i] = config[1]

    return vlan_table, switch_prio

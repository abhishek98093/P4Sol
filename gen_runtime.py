#!/usr/bin/env python3
"""
gen_runtime.py — write switch_config/sN_runtime.txt for the 5-switch topology.

Topology:
    s11 (central)
    s1, s2, s3, s4 (edges), 15 hosts each = 60 hosts

Port layout:
    Edge sN     : host ports 0..14, uplink to s11 on port 15
    Central s11 : s1 on port 0, s2 on port 1, s3 on port 2, s4 on port 3

MAC scheme:
    Host on edge N (1..4), host J (1..15):
        00:00:00:00:0N:0J   (hex)
"""

import os

CFGDIR         = "switch_config"
ROOT           = 11
EDGE_SWITCHES  = [1, 2, 3, 4]
HOSTS_PER_EDGE = 15
ALL_SWITCHES   = EDGE_SWITCHES + [ROOT]


def mac(edge_id, host_idx):
    """edge_id 1..4, host_idx 1..15 → 00:00:00:00:0N:0J (hex)."""
    return f"00:00:00:00:{edge_id:02x}:{host_idx:02x}"


def all_host_macs():
    return {sw: [mac(sw, j) for j in range(1, HOSTS_PER_EDGE + 1)]
            for sw in EDGE_SWITCHES}


def multicast_block(num_data_ports):
    """
    Split-horizon: one multicast group per ingress port, containing
    every other data port. Group ID = ingress_port + 1.
    """
    lines = []
    handle = 0
    for ingress in range(num_data_ports):
        gid = ingress + 1
        lines.append(f"mc_mgrp_create {gid}")
        others = [p for p in range(num_data_ports) if p != ingress]
        first = handle
        for egress in others:
            lines.append(f"mc_node_create {handle} {egress}")
            handle += 1
        for h in range(first, handle):
            lines.append(f"mc_node_associate {gid} {h}")
    return lines


def header(sw_id):
    return [
        f"table_add tbl_switch_id set_switch_id => {sw_id}",
        "mirroring_add 100 255",
    ]


def central_lines():
    """s11: 4 data ports → s1 (0), s2 (1), s3 (2), s4 (3)."""
    macs = all_host_macs()
    out = header(ROOT)
    out += multicast_block(len(EDGE_SWITCHES))       # 4 data ports
    for port, sw in enumerate(EDGE_SWITCHES):        # ports 0,1,2,3
        for m in macs[sw]:
            out.append(f"table_add tbl_l2 l2_forward {m} => {port}")
    return out


def edge_lines(sw_id):
    """Edge sN: 16 data ports → hosts 0..14, uplink 15."""
    macs = all_host_macs()
    out = header(sw_id)
    out += multicast_block(HOSTS_PER_EDGE + 1)       # 16 data ports
    # local hosts → ports 0..14
    for j, m in enumerate(macs[sw_id]):
        out.append(f"table_add tbl_l2 l2_forward {m} => {j}")
    # every other edge's hosts → uplink port 15
    for other in EDGE_SWITCHES:
        if other == sw_id:
            continue
        for m in macs[other]:
            out.append(f"table_add tbl_l2 l2_forward {m} => {HOSTS_PER_EDGE}")
    return out


def main():
    os.makedirs(CFGDIR, exist_ok=True)
    total = 0
    for sw in ALL_SWITCHES:
        if sw == ROOT:
            lines = central_lines()
        else:
            lines = edge_lines(sw)
        path = os.path.join(CFGDIR, f"s{sw}_runtime.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        total += len(lines)
        print(f"wrote {path}  ({len(lines)} lines)")
    print(f"\nDone. {len(ALL_SWITCHES)} files, {total} lines total.")


if __name__ == "__main__":
    main()

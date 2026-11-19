#!/usr/bin/env python3
r"""
topology.py — 5-switch ARP Flood Detection Topology (self-locating)
====================================================================
Architecture:

              s11 (central)
            /   |   |   \
          s1    s2  s3   s4       (4 edge switches)
          |     |   |    |
        15     15  15   15 hosts  (60 hosts total)

MAC scheme:
    Host on edge switch sN, host j → MAC = 00:00:00:00:0N:0j

Port layout:
    Edge sN     : host ports 0..14, uplink to s11 on port 15
    Central s11 : s1 on port 0, s2 on port 1, s3 on port 2, s4 on port 3

Fixes applied:
  * tbl_switch_id is a KEYLESS table (no match key). BMv2's CLI expects
    `table_set_default <table> <action> <param>` for keyless tables —
    NOT `table_add`. Using `table_add` results in
    "Error: Action MyIngress.set_switch_id needs 1 parameters" and the
    default action stays at set_switch_id(0), causing every digest to
    carry switch_id=0 (rejected by the controller).
  * configure() now scans simple_switch_CLI stdout for error lines
    (CLI always returns rc=0 even on per-command failures).
  * configure() verifies tbl_switch_id was actually set, via
    `table_dump` matching the hex value of the expected switch_id.
  * main() reports which switches failed configuration.
"""

import os, sys, time, subprocess
from mininet.net   import Mininet
from mininet.node  import Host, Switch
from mininet.link  import TCLink
from mininet.cli   import CLI
from mininet.log   import setLogLevel, info, error
from mininet.clean import cleanup

# ── Self-locating base ────────────────────────────────────────────────────────
BASE   = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
P4JSON = os.path.join(BASE, "build/arp_monitor_baseline.json")
LOGDIR = "/tmp/bmv2_logs"
CFGDIR = os.path.join(BASE, "switch_config")
os.makedirs(LOGDIR, exist_ok=True)
os.makedirs(CFGDIR, exist_ok=True)

print(f"[TOPO] BASE   = {BASE}")
print(f"[TOPO] P4JSON = {P4JSON}")
print(f"[TOPO] CFGDIR = {CFGDIR}")

# ── Topology parameters ───────────────────────────────────────────────────────
HOSTS_PER_EDGE = 15
ROOT           = 11
EDGE_SWITCHES  = [1, 2, 3, 4]
ALL_SWITCH_NUMS = EDGE_SWITCHES + [ROOT]


def compute_mac_tables():
    """
    Returns mac_tables[sw_num] = {mac: bmv2_port}.

    - Edge sN: host ports 0..H-1 (H = HOSTS_PER_EDGE = 15),
               uplink to central on port H (=15)
    - Central s11: s1 on port 0, s2 on port 1, s3 on port 2, s4 on port 3
    """
    H = HOSTS_PER_EDGE
    UPLINK_PORT = H  # 15

    sw_hosts = {sw: [] for sw in EDGE_SWITCHES}
    for sw in EDGE_SWITCHES:
        for j in range(1, H + 1):
            mac = f"00:00:00:00:{sw:02x}:{j:02x}"
            sw_hosts[sw].append(mac)

    tables = {sw: {} for sw in ALL_SWITCH_NUMS}

    # ── Edge switches ────────────────────────────────────────────────
    for sw in EDGE_SWITCHES:
        for idx, mac in enumerate(sw_hosts[sw]):
            tables[sw][mac] = idx                        # local hosts → 0..H-1
        for other in EDGE_SWITCHES:
            if other == sw:
                continue
            for mac in sw_hosts[other]:
                tables[sw][mac] = UPLINK_PORT            # remote hosts → H

    # ── Central switch ───────────────────────────────────────────────
    for port, sw in enumerate(EDGE_SWITCHES):
        for mac in sw_hosts[sw]:
            tables[ROOT][mac] = port

    return tables, sw_hosts


class P4Switch(Switch):
    def __init__(self, name, sw_id, json_path=P4JSON, **kwargs):
        kwargs.setdefault('failMode', 'standalone')
        super().__init__(name, **kwargs)
        self.sw_id       = sw_id
        self.json_path   = json_path
        self.thrift_port = 9090 + (sw_id - 1) * 10
        self.log_file    = os.path.join(LOGDIR, f"{name}.log")
        self.proc        = None
        self.cpu_intf    = f"{name}-cpu0"
        self.cpu_ctrl    = f"{name}-cpu1"

    def _create_cpu_veth(self):
        os.system(f"ip link del {self.cpu_intf} 2>/dev/null || true")
        os.system(f"ip link add {self.cpu_intf} type veth peer name {self.cpu_ctrl}")
        os.system(f"ip link set {self.cpu_intf} up")
        os.system(f"ip link set {self.cpu_ctrl} up")

    def start(self, controllers):
        self._create_cpu_veth()
        iface_args = []
        port_idx = 0
        for intf in self.intfList():
            if intf.name == "lo":
                continue
            iface_args += ["-i", f"{port_idx}@{intf.name}"]
            port_idx += 1
        iface_args += ["-i", f"255@{self.cpu_intf}"]

        cmd = [
            "simple_switch",
            "--device-id",   str(self.sw_id),
            "--thrift-port", str(self.thrift_port),
            "--log-file",    self.log_file,
            "--log-flush",
            "--log-level",   "warn",
        ] + iface_args + [self.json_path]

        with open(self.log_file, "w") as lf:
            self.proc = subprocess.Popen(cmd, stdout=lf, stderr=lf, close_fds=True)

    def stop(self, deleteIntfs=True):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:    self.proc.wait(timeout=3)
            except: self.proc.kill()
        os.system(f"ip link del {self.cpu_intf} 2>/dev/null || true")
        super().stop(deleteIntfs)

    # ── CLI helpers ────────────────────────────────────────────────────
    def _run_cli(self, commands: str):
        """Run simple_switch_CLI with a command string; return (rc, out, err)."""
        try:
            r = subprocess.run(
                ["simple_switch_CLI", "--thrift-port", str(self.thrift_port)],
                input=commands, capture_output=True, text=True, timeout=30,
            )
            return r.returncode, r.stdout or "", r.stderr or ""
        except subprocess.TimeoutExpired:
            return 124, "", "simple_switch_CLI timed out"

    def _verify_switch_id(self, expected: int) -> bool:
        """
        Verify tbl_switch_id's default action carries the expected value.

        `table_dump tbl_switch_id` prints:
            Action entry: MyIngress.set_switch_id - 01
        The trailing value is hex: 01 for sw1, 0b for sw11, etc.
        """
        _, out, _ = self._run_cli("table_dump tbl_switch_id\n")
        expected_hex = f"{expected:02x}"
        for line in out.splitlines():
            if "set_switch_id" in line and "-" in line:
                val = line.rsplit("-", 1)[-1].strip()
                if val == expected_hex:
                    return True
        return False

    def configure(self, mac_table, switch_type):
        """
        Configure split-horizon multicast groups, L2 entries, switch_id,
        and CPU mirroring.

        Keyless tables (tbl_switch_id) → `table_set_default` (no key).
        Keyed tables   (tbl_l2)        → `table_add ... <key> => <param>`.
        """
        data_ports = []
        port_idx = 0
        for intf in self.intfList():
            if intf.name != "lo":
                data_ports.append(port_idx)
                port_idx += 1

        num_ports = len(data_ports)

        lines = []

        # ── Keyless table → table_set_default ────────────────────────
        lines.append(f"table_set_default tbl_switch_id set_switch_id {self.sw_id}")

        lines.append("mirroring_add 100 255")

        handle = 0
        for ingress in data_ports:
            group_id = ingress + 1
            lines.append(f"mc_mgrp_create {group_id}")

            egress_ports = [p for p in data_ports if p != ingress]
            first_handle = handle
            for egress in egress_ports:
                lines.append(f"mc_node_create {handle} {egress}")
                handle += 1
            for h in range(first_handle, handle):
                lines.append(f"mc_node_associate {group_id} {h}")

        # ── Keyed table → table_add with `=>` ────────────────────────
        for mac, port in sorted(mac_table.items()):
            lines.append(f"table_add tbl_l2 l2_forward {mac} => {port}")

        cfg_path = os.path.join(CFGDIR, f"{self.name}_runtime.txt")
        with open(cfg_path, "w") as f:
            f.write("\n".join(lines) + "\n")

        rc, out, err = self._run_cli(open(cfg_path).read())

        # simple_switch_CLI returns rc=0 even when individual commands fail.
        # Scan the output for error keywords.
        combined = (out or "") + "\n" + (err or "")
        error_lines = [
            l for l in combined.splitlines()
            if any(tok in l.lower() for tok in
                   ["error", "invalid", "failed", "cannot", "no such"])
        ]

        # Verify switch_id was actually applied
        switch_id_ok = self._verify_switch_id(self.sw_id)

        if rc != 0 or error_lines or not switch_id_ok:
            info(f"  [{self.name}] ✗ configure FAILED ({switch_type})\n")
            if rc != 0:
                info(f"     CLI exit rc={rc}\n")
            for e in error_lines[:8]:
                info(f"     {e}\n")
            if not switch_id_ok:
                info(f"     tbl_switch_id value not set to {self.sw_id} "
                     f"(expected hex {self.sw_id:02x})\n")
                info(f"     config file: {cfg_path}\n")
                _, out2, _ = self._run_cli("table_dump tbl_switch_id\n")
                for l in out2.splitlines():
                    if "set_switch_id" in l:
                        info(f"     > {l}\n")
        else:
            info(f"  [{self.name}] ✓ configured ({switch_type}) "
                 f"switch_id={self.sw_id} groups={num_ports} "
                 f"entries={len(mac_table)}\n")


def main():
    setLogLevel("info")
    cleanup()

    if not os.path.exists(P4JSON):
        error(f"\n[!] {P4JSON} not found. Run ./compile.sh from {BASE} first.\n")
        sys.exit(1)

    total_hosts = len(EDGE_SWITCHES) * HOSTS_PER_EDGE
    info("\n" + "=" * 60 + "\n")
    info(f"[TOPO] Tree: s{ROOT}(central) → {EDGE_SWITCHES}(edges) → "
         f"{total_hosts} hosts\n")
    info("=" * 60 + "\n")

    info("[TOPO] Computing MAC tables...\n")
    mac_tables, _ = compute_mac_tables()

    net = Mininet(controller=None, switch=P4Switch, host=Host,
                  link=TCLink, autoSetMacs=False, autoStaticArp=False)

    info("[TOPO] Adding switches...\n")
    switches = {}
    for sw_num in ALL_SWITCH_NUMS:
        sw = net.addSwitch(f"s{sw_num}", cls=P4Switch,
                           sw_id=sw_num, json_path=P4JSON)
        switches[f"s{sw_num}"] = sw

    info(f"[TOPO] Adding {total_hosts} hosts "
         f"({HOSTS_PER_EDGE} per edge switch)...\n")
    host_idx = 1
    for sw_num in EDGE_SWITCHES:
        for j in range(1, HOSTS_PER_EDGE + 1):
            mac = f"00:00:00:00:{sw_num:02x}:{j:02x}"
            ip  = f"10.{sw_num}.{j}.1/8"
            h = net.addHost(f"h{host_idx}", ip=ip, mac=mac)
            net.addLink(h, switches[f"s{sw_num}"])
            host_idx += 1

    info("[TOPO] Adding uplinks (edges → central)...\n")
    for sw_num in EDGE_SWITCHES:
        net.addLink(switches[f"s{sw_num}"], switches[f"s{ROOT}"])

    info("\n[TOPO] Starting network...\n")
    net.start()

    info("\n[TOPO] Waiting for Thrift ports to bind...\n")
    time.sleep(6)

    info("\n[TOPO] Configuring switches...\n")
    failed = []
    for name, sw in switches.items():
        sw_num = int(name[1:])
        kind = "central" if sw_num == ROOT else "edge"
        sw.configure(mac_tables[sw_num], kind)
        if not sw._verify_switch_id(sw.sw_id):
            failed.append(name)

    if failed:
        info("\n" + "!" * 60 + "\n")
        info(f"[TOPO] ⚠ CONFIGURATION FAILED ON: {', '.join(failed)}\n")
        info(f"[TOPO]   These switches still have tbl_switch_id empty or\n")
        info(f"[TOPO]   set to the wrong value. The controller's edge-only\n")
        info(f"[TOPO]   port filter will reject their digests. Fix before\n")
        info(f"[TOPO]   running the controller.\n")
        info("!" * 60 + "\n")
    else:
        info("\n[TOPO] ✓ All switches report tbl_switch_id populated.\n")

    ifaces = " ".join(switches[f"s{i}"].cpu_ctrl for i in ALL_SWITCH_NUMS)

    info("\n" + "=" * 60)
    info(f"\n[TOPO] NETWORK READY "
         f"({len(ALL_SWITCH_NUMS)} switches, {total_hosts} hosts)\n")
    info("=" * 60)
    info("\nTo start the controller:\n")
    info(f"  sudo python3 {BASE}/controller/controller.py \\\n")
    info(f"    --interfaces {ifaces} --label normal\n")
    info("\nConnectivity tests:\n")
    info("  Same edge:     h1  ping -c 3 10.1.2.1\n")
    info("  Edge1→Edge2:   h1  ping -c 3 10.2.1.1\n")
    info("  Edge1→Edge3:   h1  ping -c 3 10.3.1.1\n")
    info("  Edge1→Edge4:   h1  ping -c 3 10.4.1.1\n")
    info("  Reverse:       h46 ping -c 3 10.1.1.1\n")
    info("=" * 60 + "\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()

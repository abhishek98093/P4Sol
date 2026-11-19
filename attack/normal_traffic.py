#!/usr/bin/env python3
"""Realistic normal traffic generator for the 60-host topology."""
import argparse, os, random, socket, subprocess, sys, threading, time
try:
    from scapy.all import Ether, ARP, sendp, get_if_hwaddr, get_if_addr
except ImportError:
    sys.stderr.write("scapy required: sudo apt install python3-scapy\n")
    sys.exit(1)

ALL_HOSTS = [f"10.{sw}.{j}.1" for sw in (1, 2, 3, 4) for j in range(1, 16)]
SERVER_PORTS = [22, 80, 443, 8080, 5000]

PROFILES = {
    "quiet": {
        "mean_gap": 3.5, "grat_min": 60, "grat_max": 180,
        "idle_pmin": 20, "idle_pmax": 60, "idle_dmin": 8, "idle_dmax": 25,
        "ni_min": 20, "ni_max": 60, "clamp": 8.0,
        "acts": [("tcp_connect",25),("ping",30),("ping_burst",5),
                 ("multi_ping",2),("arp_req",8),("tcp_exchange",15),("idle",15)],
    },
    "normal": {
        "mean_gap": 1.2, "grat_min": 30, "grat_max": 120,
        "idle_pmin": 15, "idle_pmax": 40, "idle_dmin": 5, "idle_dmax": 15,
        "ni_min": 30, "ni_max": 90, "clamp": 6.0,
        "acts": [("tcp_exchange",35),("tcp_connect",20),("ping",15),
                 ("ping_burst",10),("multi_ping",8),("arp_req",7),("idle",5)],
    },
    "busy": {
        "mean_gap": 0.4, "grat_min": 20, "grat_max": 60,
        "idle_pmin": 30, "idle_pmax": 80, "idle_dmin": 2, "idle_dmax": 5,
        "ni_min": 60, "ni_max": 180, "clamp": 3.0,
        "acts": [("tcp_exchange",40),("tcp_connect",22),("ping",10),
                 ("ping_burst",10),("multi_ping",10),("arp_req",5),("idle",3)],
    },
}

def pick_target(my_ip):
    c = [ip for ip in ALL_HOSTS if ip != my_ip]
    return random.choice(c) if c else None

def pick_targets(my_ip, k):
    c = [ip for ip in ALL_HOSTS if ip != my_ip]
    return random.sample(c, min(k, len(c)))

def pgap(mean):
    return random.expovariate(1.0 / max(mean, 0.01))

def a_ping(t):
    subprocess.run(["ping","-c","1","-W","1",t],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return f"ping {t}"

def a_burst(t):
    n = random.randint(3,6)
    subprocess.run(["ping","-c",str(n),"-i","0.2","-W","1",t],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return f"burst x{n} {t}"

def a_tcpc(t):
    p = random.choice(SERVER_PORTS)
    subprocess.run(["nc","-zw1",t,str(p)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return f"tcp-conn {t}:{p}"

def a_tcpx(t):
    p = random.choice(SERVER_PORTS)
    try:
        with socket.create_connection((t, p), timeout=1.5) as s:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            try: s.settimeout(0.8); s.recv(512)
            except (socket.timeout, OSError): pass
    except (socket.timeout, OSError): pass
    return f"tcp-exch {t}:{p}"

def a_mping(my_ip):
    for t in pick_targets(my_ip, random.randint(3,5)):
        subprocess.run(["ping","-c","1","-W","1",t],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(random.uniform(0.05, 0.2))
    return "multi-ping"

def a_arp(iface, mac, ip, t):
    sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
          ARP(op=1, hwsrc=mac, psrc=ip,
              hwdst="00:00:00:00:00:00", pdst=t),
          iface=iface, verbose=False)
    return f"arp-req {t}"

def a_grat(iface, mac, ip):
    sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
          ARP(op=1, hwsrc=mac, psrc=ip,
              hwdst="ff:ff:ff:ff:ff:ff", pdst=ip),
          iface=iface, verbose=False)
    return "grat-arp"

def srv_loop(port, stop):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port)); s.listen(8); s.settimeout(0.5)
    except OSError:
        return
    while not stop.is_set():
        try: conn, _ = s.accept()
        except socket.timeout: continue
        except OSError: break
        try:
            conn.settimeout(0.5)
            try: conn.recv(512)
            except (socket.timeout, OSError): pass
            try: conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except OSError: pass
        finally:
            try: conn.close()
            except OSError: pass
    try: s.close()
    except OSError: pass

def start_srv(ports):
    stop = threading.Event()
    th = []
    for p in ports:
        t = threading.Thread(target=srv_loop, args=(p, stop), daemon=True)
        t.start(); th.append(t)
    return th, stop

def client_loop(iface, mac, ip, dur, prof, verbose):
    pool = []
    for name, w in prof["acts"]:
        pool.extend([name] * w)
    t0 = time.time(); t_end = t0 + dur; n = 0
    next_grat = t0 + random.uniform(prof["grat_min"], prof["grat_max"])
    next_idle = t0 + random.uniform(prof["idle_pmin"], prof["idle_pmax"])
    while time.time() < t_end:
        now = time.time()
        if now >= next_grat:
            try: a_grat(iface, mac, ip)
            except Exception: pass
            next_grat = now + random.uniform(prof["grat_min"], prof["grat_max"])
        if now >= next_idle:
            idle = random.uniform(prof["idle_dmin"], prof["idle_dmax"])
            time.sleep(min(idle, max(0, t_end - time.time())))
            next_idle = time.time() + random.uniform(prof["ni_min"], prof["ni_max"])
            continue
        choice = random.choice(pool)
        tgt = pick_target(ip)
        if tgt is None: break
        try:
            if   choice == "tcp_exchange": a_tcpx(tgt)
            elif choice == "tcp_connect":  a_tcpc(tgt)
            elif choice == "ping":         a_ping(tgt)
            elif choice == "ping_burst":   a_burst(tgt)
            elif choice == "multi_ping":   a_mping(ip)
            elif choice == "arp_req":      a_arp(iface, mac, ip, tgt)
            elif choice == "idle":         time.sleep(random.uniform(1.0, 3.0))
        except Exception:
            pass
        n += 1
        if verbose: print(f"[normal] +{time.time()-t0:5.1f}s {choice}")
        g = max(0.05, min(pgap(prof["mean_gap"]), prof["clamp"]))
        time.sleep(g)
    return n

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--role", choices=["client","server","peer"], default="client")
    ap.add_argument("--intensity", choices=["quiet","normal","busy"], default="normal")
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("needs root")
    try:
        mac = get_if_hwaddr(a.iface); ip = get_if_addr(a.iface)
    except Exception as e:
        sys.exit(f"iface read failed: {e}")
    prof = PROFILES[a.intensity]
    print(f"[normal] iface={a.iface} src={ip} ({mac})")
    print(f"[normal] role={a.role} intensity={a.intensity} dur={a.duration}s")
    th, stop = [], None
    if a.role in ("server","peer"):
        th, stop = start_srv(SERVER_PORTS)
    t0 = time.time()
    try:
        if a.role in ("client","peer"):
            n = client_loop(a.iface, mac, ip, a.duration, prof, a.verbose)
        else:
            end = t0 + a.duration
            while time.time() < end: time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if stop: stop.set()
        for t in th: t.join(timeout=1.0)

if __name__ == "__main__":
    main()

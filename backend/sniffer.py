import sqlite3
import hashlib
from scapy.all import sniff, TCP, IP, Raw

DB_PATH = "/opt/corvus-sentinel/data/sentinel.db"

def parse_packet(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    tcp_layer = pkt[TCP]
    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    src_port = tcp_layer.sport
    dst_port = tcp_layer.dport

    # 1. Capture du SYN (Empreinte OS)
    if tcp_layer.flags == "S":
        ttl = ip_layer.ttl
        hops = 128 - ttl if ttl <= 128 else 255 - ttl
        win_size = tcp_layer.window
        
        mss = None
        wscale = None
        for opt, val in tcp_layer.options:
            if opt == 'MSS':
                mss = val
            elif opt == 'WScale':
                wscale = val

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO telemetry (
                    server_port, ip, src_port, ttl, hops, mss, win_size, wscale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (dst_port, src_ip, src_port, ttl, hops, mss, win_size, wscale))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return

    # 2. Capture des canaux Custom (minecraft:register)
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        if b"minecraft:register" in payload:
            idx = payload.find(b"minecraft:register") + len(b"minecraft:register")
            raw_mods = payload[idx:].split(b"\x00\x00")[0]
            cleaned_mods = "".join([chr(b) if 32 <= b <= 126 else ";" for b in raw_mods]).strip(";")
            
            if len(cleaned_mods) > 3 and ";" in cleaned_mods:
                ch_hash = hashlib.sha256(cleaned_mods.encode('utf-8')).hexdigest()[:16]
                try:
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute("""
                        UPDATE telemetry 
                        SET channels_hash = ?, raw_channels = ?
                        WHERE ip = ? AND src_port = ?
                    """, (ch_hash, cleaned_mods, src_ip, src_port))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

if __name__ == "__main__":
    sniff(prn=parse_packet, store=False)

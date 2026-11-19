/* ============================================================
 * arp_monitor.p4 — ARP Flood Detection, P4_16 v1model / BMv2
 *
 * Sampling strategy (edge-origin only):
 *   Counters increment ONLY on edge switches (switch_id != 11) AND
 *   ONLY on host ports (ingress_port < 15). Every ARP packet — request
 *   OR reply — is counted exactly once, at the edge switch where the
 *   originating host sent it. Forwarded copies (arriving on uplink
 *   port 15 or via central switch s11) are skipped.
 *
 *   Every 3rd ARP packet triggers a digest (SAMPLE_EVERY = 3) and a
 *   clone to CPU port 255. The 45-byte CPU header carries:
 *     switch_id, ingress_port, sender_ip/mac, target_ip, opcode,
 *     reg_arp_total, reg_arp_request, reg_arp_reply, reg_gratuitous,
 *     reg_broadcast, reg_sample_counter, reg_self_mac_mismatch.
 *
 * Blocking (additive, disabled by default):
 *   tbl_block_ip   — keyed on hdr.arp.sender_ip
 *   tbl_block_port — keyed on std_meta.ingress_port
 *   Both default to no_block(). When empty, behaviour is identical
 *   to a monitoring-only program.
 *
 * Forwarding is UNCHANGED across all switches and ports — the
 * monitoring guard does not affect tbl_l2 or the mcast flood.
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ARP_OP_REQUEST = 1;
const bit<16> ARP_OP_REPLY   = 2;
const bit<48> BROADCAST_MAC  = 0xFFFFFFFFFFFF;
const bit<9>  CPU_PORT       = 255;
const bit<8>  SAMPLE_EVERY   = 3;      // ← was 10; sample every 3rd ARP
const bit<32> CLONE_SESSION  = 100;

// ── Headers ───────────────────────────────────────────────────────────────────
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_len;
    bit<8>  proto_len;
    bit<16> opcode;
    bit<48> sender_mac;
    bit<32> sender_ip;
    bit<48> target_mac;
    bit<32> target_ip;
}

// 45-byte cpu_header_t — exact layout the controller expects
header cpu_header_t {
    bit<8>  reason;
    bit<8>  switch_id;
    bit<9>  ingress_port;
    bit<7>  _pad;
    bit<32> sender_ip;
    bit<48> sender_mac;
    bit<32> target_ip;
    bit<16> opcode;
    bit<32> reg_arp_total;
    bit<32> reg_arp_request;
    bit<32> reg_arp_reply;
    bit<32> reg_gratuitous;
    bit<32> reg_broadcast;
    bit<8>  reg_sample_counter;
    bit<32> reg_self_mac_mismatch;
}

struct headers_t {
    cpu_header_t cpu_hdr;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
}

struct metadata_t {
    @field_list(0) bit<8>  switch_id;
    @field_list(0) bit<1>  do_clone;
    @field_list(0) bit<7>  _pad;
    @field_list(0) bit<32> snap_total;
    @field_list(0) bit<32> snap_request;
    @field_list(0) bit<32> snap_reply;
    @field_list(0) bit<32> snap_gratuitous;
    @field_list(0) bit<32> snap_broadcast;
    @field_list(0) bit<8>  snap_counter;
    @field_list(0) bit<32> snap_self_mismatch;
}

// ── Registers ─────────────────────────────────────────────────────────────────
register<bit<32>>(1) reg_arp_total;
register<bit<32>>(1) reg_arp_request;
register<bit<32>>(1) reg_arp_reply;
register<bit<32>>(1) reg_gratuitous;
register<bit<32>>(1) reg_broadcast;
register<bit<8>>(1)  reg_sample_counter;
register<bit<32>>(1) reg_self_mac_mismatch;

// ── Parser ────────────────────────────────────────────────────────────────────
parser MyParser(packet_in        pkt,
                out headers_t    hdr,
                inout metadata_t meta,
                inout standard_metadata_t std_meta)
{
    state start { transition parse_ethernet; }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }
    state parse_arp  { pkt.extract(hdr.arp);  transition accept; }
    state parse_ipv4 { pkt.extract(hdr.ipv4); transition accept; }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ── Ingress ───────────────────────────────────────────────────────────────────
control MyIngress(inout headers_t    hdr,
                  inout metadata_t   meta,
                  inout standard_metadata_t std_meta)
{
    action set_switch_id(bit<8> sw_id) { meta.switch_id = sw_id; }
    table tbl_switch_id {
        actions        = { set_switch_id; }
        default_action = set_switch_id(0);
        size           = 1;
    }

    action l2_forward(bit<9> port) { std_meta.egress_spec = port; }
    action drop()                  { mark_to_drop(std_meta); }

    table tbl_l2 {
        key            = { hdr.ethernet.dst_addr : exact; }
        actions        = { l2_forward; drop; }
        default_action = drop();
        size           = 1024;
    }

    // Blocking actions
    action no_block() { }
    action block_source() { }   // drop executed by caller

    table tbl_block_ip {
        key            = { hdr.arp.sender_ip : exact; }
        actions        = { block_source; no_block; }
        default_action = no_block();
        size           = 256;
    }

    table tbl_block_port {
        key            = { std_meta.ingress_port : exact; }
        actions        = { block_source; no_block; }
        default_action = no_block();
        size           = 32;
    }

    apply {
        tbl_switch_id.apply();
        meta.do_clone = 0;

        if (hdr.arp.isValid()) {

            // ── Block check first (drop wins on any switch/port) ────────
            if (tbl_block_ip.apply().hit || tbl_block_port.apply().hit) {
                mark_to_drop(std_meta);
                return;
            }

            // ── Monitoring: ONLY on edge host ports (origin) ────────────
            // switch_id != 11 → skip central switch s11
            // ingress_port < 15 → skip uplink ports (port 15)
            // This is exactly "the packet is originating from a host on
            // an edge switch" — forwarded copies are silently ignored.
            if (meta.switch_id != 11 && std_meta.ingress_port < 15) {

                bit<1> is_request    = (hdr.arp.opcode == ARP_OP_REQUEST)       ? 1w1 : 1w0;
                bit<1> is_reply      = (hdr.arp.opcode == ARP_OP_REPLY)         ? 1w1 : 1w0;
                bit<1> is_gratuitous = (hdr.arp.sender_ip == hdr.arp.target_ip) ? 1w1 : 1w0;
                bit<1> is_broadcast  = (hdr.ethernet.dst_addr == BROADCAST_MAC) ? 1w1 : 1w0;
                bit<1> is_mismatch   = (hdr.ethernet.src_addr != hdr.arp.sender_mac) ? 1w1 : 1w0;

                bit<32> cur_total; bit<32> cur_req; bit<32> cur_rep;
                bit<32> cur_grat;  bit<32> cur_bcast; bit<8> cur_ctr; bit<32> cur_mm;

                reg_arp_total.read(cur_total,    0);
                reg_arp_request.read(cur_req,    0);
                reg_arp_reply.read(cur_rep,      0);
                reg_gratuitous.read(cur_grat,    0);
                reg_broadcast.read(cur_bcast,    0);
                reg_sample_counter.read(cur_ctr, 0);
                reg_self_mac_mismatch.read(cur_mm, 0);

                cur_total = cur_total + 1;
                cur_ctr   = cur_ctr   + 1;
                if (is_request    == 1) { cur_req   = cur_req   + 1; }
                if (is_reply      == 1) { cur_rep   = cur_rep   + 1; }
                if (is_gratuitous == 1) { cur_grat  = cur_grat  + 1; }
                if (is_broadcast  == 1) { cur_bcast = cur_bcast + 1; }
                if (is_mismatch   == 1) { cur_mm    = cur_mm    + 1; }

                // Fire every SAMPLE_EVERY-th ARP (requests AND replies count)
                if (cur_ctr >= SAMPLE_EVERY) {
                    meta.snap_total         = cur_total;
                    meta.snap_request       = cur_req;
                    meta.snap_reply         = cur_rep;
                    meta.snap_gratuitous    = cur_grat;
                    meta.snap_broadcast     = cur_bcast;
                    meta.snap_counter       = cur_ctr;
                    meta.snap_self_mismatch = cur_mm;
                    meta.do_clone           = 1;
                    cur_total = 0; cur_req = 0; cur_rep = 0;
                    cur_grat  = 0; cur_bcast = 0; cur_ctr = 0; cur_mm = 0;
                }

                reg_arp_total.write(0,        cur_total);
                reg_arp_request.write(0,      cur_req);
                reg_arp_reply.write(0,        cur_rep);
                reg_gratuitous.write(0,       cur_grat);
                reg_broadcast.write(0,        cur_bcast);
                reg_sample_counter.write(0,   cur_ctr);
                reg_self_mac_mismatch.write(0, cur_mm);

                if (meta.do_clone == 1) {
                    clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 0);
                }
            }

            // ── Forwarding (always runs, all switches, all ports) ───────
            if (hdr.ethernet.dst_addr == BROADCAST_MAC) {
                std_meta.mcast_grp = (bit<16>)std_meta.ingress_port + 1;
            } else {
                tbl_l2.apply();
            }

        } else {
            tbl_l2.apply();
        }
    }
}

// ── Egress ────────────────────────────────────────────────────────────────────
control MyEgress(inout headers_t    hdr,
                 inout metadata_t   meta,
                 inout standard_metadata_t std_meta)
{
    apply {
        if (std_meta.egress_port == std_meta.ingress_port) {
            mark_to_drop(std_meta);
            return;
        }

        if (std_meta.egress_port == CPU_PORT) {
            hdr.cpu_hdr.setValid();
            hdr.cpu_hdr.reason                = 0xAA;
            hdr.cpu_hdr.switch_id             = meta.switch_id;
            hdr.cpu_hdr.ingress_port          = std_meta.ingress_port;
            hdr.cpu_hdr._pad                  = 0;
            hdr.cpu_hdr.sender_ip             = hdr.arp.sender_ip;
            hdr.cpu_hdr.sender_mac            = hdr.arp.sender_mac;
            hdr.cpu_hdr.target_ip             = hdr.arp.target_ip;
            hdr.cpu_hdr.opcode                = hdr.arp.opcode;
            hdr.cpu_hdr.reg_arp_total         = meta.snap_total;
            hdr.cpu_hdr.reg_arp_request       = meta.snap_request;
            hdr.cpu_hdr.reg_arp_reply         = meta.snap_reply;
            hdr.cpu_hdr.reg_gratuitous        = meta.snap_gratuitous;
            hdr.cpu_hdr.reg_broadcast         = meta.snap_broadcast;
            hdr.cpu_hdr.reg_sample_counter    = meta.snap_counter;
            hdr.cpu_hdr.reg_self_mac_mismatch = meta.snap_self_mismatch;
        }
    }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ── Deparser ──────────────────────────────────────────────────────────────────
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.cpu_hdr);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.arp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

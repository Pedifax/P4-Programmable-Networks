/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_PROBE = 0x812;
const bit<48> H1_MAC_ADDR = 0x080000000111;
const bit<48> DELTA = 48w100000;
const bit<16> ZERO = 0x0;
const bit<32> TEN_K = 0x2710;

// last_seen_table is 48 bit because ingress_global_timestamp is 48 bit
register<bit<32>>(6) probe_data;
register<bit<48>>(10000) last_seen_table;
register<bit<14>>(10000) nhop_table;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header probe_t {
    bit<32> s1_p2_pkt_count;
    bit<32> s1_p2_bytes_count;
    bit<32> s1_p3_pkt_count;
    bit<32> s1_p3_bytes_count;
    bit<32> total_pkt_count;
    bit<32> total_output_bytes;
    bit<32> sid;
    bit<16> protocol;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<14> ecmp_select;
    bit<32> hash_value;
    bit<48> last_seen;
    bit<14> last_nhop;
    bit<16> should_flowlet;
}

struct headers {
    ethernet_t   ethernet;
    probe_t      probe;
    ipv4_t       ipv4;
    tcp_t        tcp;
}   

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_PROBE: parse_probe;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_probe{
        packet.extract(hdr.probe);
        transition select(hdr.probe.protocol){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    
    /////////////////////////////////// ACTIONS ///////////////////////////////////
    
         
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        hash(meta.ecmp_select,
        HashAlgorithm.crc16,
        ecmp_base,
        { hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.ipv4.protocol,
            hdr.tcp.srcPort,
            hdr.tcp.dstPort },
        ecmp_count);
        
        // updata table entries
        last_seen_table.write(meta.hash_value, standard_metadata.ingress_global_timestamp);
        nhop_table.write(meta.hash_value, meta.ecmp_select);
    }

    action check_time_diff(){
        /* 
        - Compute the hash value of 5 tuples (put in meta.hash_value)
        - Get the last_seen and last_nhop data from tables
        - if time diff > DELTA:
            - we simply do the normal ecmp (hash to get the nhop)
            - updata table entries
        - else:
            - we manually set meta.ecmp_select to a different port from the previous one
            - update table entries
        */

        hash(meta.hash_value,
            HashAlgorithm.crc16,
            ZERO,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort },
            TEN_K);

        // Get the last_seen and last_nhop data from tables
        last_seen_table.read(meta.last_seen, meta.hash_value);
        nhop_table.read(meta.last_nhop, meta.hash_value);

        if (standard_metadata.ingress_global_timestamp - meta.last_seen > DELTA){
            meta.should_flowlet = 1;
        }
        else{
            meta.should_flowlet = 0;
        }
    }

    action flowlet(){
        // we manually set meta.ecmp_select to a different port from the previous one
        meta.ecmp_select = meta.last_nhop;

        // update table entries
        last_seen_table.write(meta.hash_value, standard_metadata.ingress_global_timestamp);
    }

    action set_nhop(bit<48> nhop_dmac, bit<32> nhop_ipv4, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /////////////////////////////////// TABLES ///////////////////////////////////
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
    }

    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 2;
    }

    /////////////////////////////////// LOGICS ///////////////////////////////////

    // ingress logic starts here
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0){

            if (hdr.ethernet.srcAddr == H1_MAC_ADDR){

                check_time_diff();

                if (meta.should_flowlet == 1){
                    flowlet();
                }
                else{
                    ecmp_group.apply();
                }

                ecmp_nhop.apply();

                // update monitor data
                bit<32> s1_p2_pkt_count;
                bit<32> s1_p2_bytes_count;
                bit<32> s1_p3_pkt_count;
                bit<32> s1_p3_bytes_count;
                bit<32> total_pkt_count;
                bit<32> total_output_bytes;

                probe_data.read(s1_p2_pkt_count, 0);
                probe_data.read(s1_p2_bytes_count, 1);
                probe_data.read(s1_p3_pkt_count, 2);
                probe_data.read(s1_p3_bytes_count, 3);
                probe_data.read(total_pkt_count, 4);
                probe_data.read(total_output_bytes, 5);

                if (meta.ecmp_select == 0){
                    s1_p2_pkt_count = s1_p2_pkt_count + 1;
                    s1_p2_bytes_count = s1_p2_bytes_count + standard_metadata.packet_length;

                    probe_data.write(0, s1_p2_pkt_count);
                    probe_data.write(1, s1_p2_bytes_count);
                } 
                
                else{
                    s1_p3_pkt_count = s1_p3_pkt_count + 1;
                    s1_p3_bytes_count = s1_p3_bytes_count + standard_metadata.packet_length;

                    probe_data.write(2, s1_p3_pkt_count);
                    probe_data.write(3, s1_p3_bytes_count);
                }
                total_pkt_count = total_pkt_count + 1;
                total_output_bytes = total_output_bytes + standard_metadata.packet_length;
                probe_data.write(4, total_pkt_count);
                probe_data.write(5, total_output_bytes);

                hdr.probe.s1_p2_pkt_count = s1_p2_pkt_count;
                hdr.probe.s1_p2_bytes_count = s1_p2_bytes_count;
                hdr.probe.s1_p3_pkt_count = s1_p3_pkt_count;
                hdr.probe.s1_p3_bytes_count = s1_p3_bytes_count;
                hdr.probe.total_pkt_count = total_pkt_count;
                hdr.probe.total_output_bytes = total_output_bytes;
            } 

            else {
                ipv4_lpm.apply();
            }

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // the below order is important!
        packet.emit(hdr.ethernet);
        packet.emit(hdr.probe);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

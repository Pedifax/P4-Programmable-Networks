/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// define a constant. In this case a Ipv4 type
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_PROBE = 0x812;
const bit<48> H1_MAC_ADDR = 0x080000000111;

register<bit<32>>(6) probe_data;
register<bit<32>>(1) round_robin;

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
    bit<32> per_packet_select;
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

    // the below are added during the class

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
    
    action set_per_packet_select() {
        // declare a temp register to hold round_robin 
        // (or maybe directly assign round_robin to meta.per_packet_select)
        round_robin.read(meta.per_packet_select, 0);

        // if meta.per_packet_select = 0, then make it 1. Vice versa
        if (meta.per_packet_select == 0){
            meta.per_packet_select = 1;
        }
        else{
            meta.per_packet_select = 0;
        }
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

    table per_packet_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_per_packet_select;
        }
        size = 1024;
    }

    table per_packet_nhop {
        key = {
            meta.per_packet_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    /////////////////////////////////// LOGICS ///////////////////////////////////

    // ingress logic starts here
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0){

            if (hdr.ethernet.srcAddr == H1_MAC_ADDR){
                // no ecmp anymore, we use round robin
                per_packet_group.apply();
                per_packet_nhop.apply();

                // update round_robin 
                round_robin.write(0, meta.per_packet_select);

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

                if (meta.per_packet_select == 0){
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

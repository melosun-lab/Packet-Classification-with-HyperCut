/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
	bit<16>   leaf;
	bit<16>   sport;
	bit<16>   dport;
	bit<16>   index;
	bit<1>   continue;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t         tcp;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
	meta.continue = 1;
	meta.leaf = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	hdr.ipv4.tos = 77;
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	    17: parse_udp;
            default: accept;
        }
    }

     state parse_tcp {
        packet.extract(hdr.tcp);
	meta.sport = hdr.tcp.srcPort;
	meta.dport = hdr.tcp.dstPort;
        transition accept;
    }

     state parse_udp {
        packet.extract(hdr.udp);
	meta.sport = hdr.udp.srcPort;
	meta.dport = hdr.udp.dstPort;
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action null_end() {
	meta.continue = 0;
	drop();
	}

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_index(bit<16> lvl) { meta.index = lvl;}

    action set_leaf(bit<16> lvl) { meta.leaf = lvl;   meta.continue = 0;}

/* These are just the empty rules, they just tag the packet*/
    action a0() {hdr.ipv4.tos = 0;}
    action a1() {hdr.ipv4.tos = 1;}
    action a2() {hdr.ipv4.tos = 2;}
    action a3() {hdr.ipv4.tos = 3;}
    action a4() {hdr.ipv4.tos = 4;}
    action a5() {hdr.ipv4.tos = 5;}
    action a6() {hdr.ipv4.tos = 6;}
    action a7() {hdr.ipv4.tos = 7;}
    action a8() {hdr.ipv4.tos = 8;}
    action a9() {hdr.ipv4.tos = 9;}
    action a11() {hdr.ipv4.tos = 11;}

/* This is the default forwarding table, it can be ignored */
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

	table packetclassification {
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;		
		}

		actions = {
			a0;
			a1;
			a2;
			a3;
			a4;
			a5;
			a6;
			a7;
			a8;
			a9;
			a11;
			drop();
		}		

		const entries = {
			(0 .. 1, 14 .. 15,  3, 1 .. 4 , 17): a0();
			(0 .. 1, 14 .. 15, 2, 3, 17): a1();
			(0 .. 1, 8 .. 11, 1 .. 4, 3 , 6): a2();
			(0 .. 1, 8 .. 11, 1 .. 4, 2 , 6): a3();
			(0 .. 1, 8 .. 11, 3, 4 , 6): a4();
			(0 .. 7, 14 .. 15, 3, 2, 17): a5();
			(0 .. 7, 14 .. 15, 3, 3, 17): a6();
			(0 .. 7, 8 .. 15, 1 .. 4, 1 .. 4, 6): a7();
			(0 .. 15, 4 .. 7, 1 .. 4, 1 .. 4, 6): a8();
			(0 .. 15, 0 .. 7, 1 .. 4, 2, 17): a9();
			(0 .. 15, 0 .. 15, 1 .. 4, 1 .. 4, 6): a11();
		}
		default_action = drop();
	}

    apply {
	if (hdr.ipv4.isValid()) {
		ipv4_lpm.apply();	    	
		packetclassification.apply();
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
              hdr.ipv4.tos,
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
	packet.emit(hdr.udp);
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

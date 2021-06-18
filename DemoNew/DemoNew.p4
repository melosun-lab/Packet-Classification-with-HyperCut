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

/* 
	The following set of tables represents the tree structure.
     	Note that all the tables have keys of the 5 fields and they are over a range
     	A non-leaf node can only do one of 3 things
		- Indicate that there was a dead end at a null node
		- Set the index for the next node to visit
		- Set the value of the leaf that was found, and set a bit to end the search
     	A leaf node simply performs a match against all the rules in that node
*/

/* This node represents the root */
    table root {
	key = {
		hdr.ipv4.srcAddr: range;
		hdr.ipv4.dstAddr: range;
		meta.sport:range;
		meta.dport:range;
		hdr.ipv4.protocol:range;		
	}

	actions = {
		set_leaf;
		set_index;
		null_end;
	}

	/* 
		NOTE: In p4, if there are multiple keys, then a tuple is used to represent the entry to search.
		A range is marked as " a .. b " and it means "a to b", if there is only a single number then it is exact match
	*/ 
	const entries = {
		(0 .. 15, 0 .. 7, 1 .. 4 ,1 .. 2, 17): set_leaf(1);
		(0 .. 15, 0 .. 3, 1 .. 4,1 .. 4, 6): set_leaf(2);
		(0 .. 15, 0 .. 11, 1 .. 4, 3 .. 4, 17): null_end();

		(0 .. 15, 4 .. 7, 1 .. 4, 1 .. 4, 6): set_leaf(3);

		(0 .. 15, 8 .. 11, 1 .. 4, 1 .. 2, 17): null_end();
		(0 .. 15, 8 .. 11, 1 .. 4, 1 .. 2, 6): set_leaf(4);
		(0 .. 15, 8 .. 11, 1 .. 4, 3 .. 4, 6): set_index(1);

		(0 .. 15, 12 .. 15, 1 .. 4, 1 .. 2, 17): set_leaf(7);
		(0 .. 15, 12 .. 15, 1 .. 4, 1 .. 4, 6): set_leaf(8);
		(0 .. 15, 12 .. 15, 1 .. 4, 3 .. 4, 17): set_leaf(9);
	}
	default_action = null_end();
      }

	table node1 {
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;	
		}
	
		actions = {
			set_leaf;
			set_index;
			null_end;
		}

		const entries = {
			(0 .. 15, 8 .. 11, 1 .. 4, 1 .. 3, 6): set_leaf(5);
			(0 .. 15, 8 .. 11, 1 .. 4, 4, 6): set_leaf(6);
		}

		default_action = null_end();
	}

	table leaf1{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a9;
			drop();
		}

		const entries = {
			(0 .. 15, 0 .. 7, 1 .. 4, 2, 17): a9();
		}
		default_action = drop();
	}

	table leaf2{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a11;
			drop();
		}

		const entries = {
			(0 .. 15, 0 .. 15, 1 .. 4, 1 .. 4, 6): a11();
		}
		default_action = drop();
	}

	table leaf3{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a8;
			a11;
			drop();
		}

		const entries = {
			(0 .. 15, 4 .. 7, 1 .. 4, 1 .. 4, 6): a8();
			(0 .. 15, 0 .. 15, 1 .. 4, 1 .. 4, 6): a11();
		}
		default_action = drop();
	}

	table leaf4{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a3;
			a7;
			a11;
			drop();
		}

		const entries = {
			(0 .. 1, 8 .. 11, 1 .. 4, 2 , 6): a3();
			(0 .. 7, 8 .. 15, 1 .. 4, 1 .. 4, 6): a7();
			(0 .. 15, 0 .. 15, 1 .. 4, 1 .. 4, 6): a11();
		}
		default_action = drop();
	}

	table leaf5{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a2;
			a7;
			a11;
			drop();
		}

		const entries = {
			(0 .. 1, 8 .. 11, 1 .. 4, 3 , 6): a2();
			(0 .. 7, 8 .. 15, 1 .. 4, 1 .. 4, 6): a7();
			(0 .. 15, 0 .. 15, 1 .. 4, 1 .. 4, 6): a11();
		}
		default_action = drop();
	}

	table leaf6{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a4;
			a7;
			a11;
			drop();
		}

		const entries = {
			(0 .. 1, 8 .. 11, 3, 4 , 6): a4();
			(0 .. 7, 8 .. 15, 1 .. 4, 1 .. 4, 6): a7();
			(0 .. 15, 0 .. 15, 1 .. 4, 1 .. 4, 6): a11();
		}
		default_action = drop();
	}	

	table leaf7{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a0;
			a5;
			drop();
		}

		const entries = {
			(0 .. 1, 14 .. 15,  3, 1 .. 4 , 17): a0();
			(0 .. 7, 14 .. 15, 3, 2, 17): a5();
		}
		default_action = drop();
	}	

	table leaf8{
		key = {
			hdr.ipv4.srcAddr: range;
			hdr.ipv4.dstAddr: range;
			meta.sport:range;
			meta.dport:range;
			hdr.ipv4.protocol:range;
		}

		actions = {
			a7;
			a11;
			drop();
		}

		const entries = {
			(0 .. 7, 8 .. 15, 1 .. 4, 1 .. 4, 6): a7();
			(0 .. 15, 0 .. 15, 1 .. 4, 1 .. 4, 6): a11();
		}
		default_action = drop();
	}

	table leaf9{
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
			a6;
			drop();
		}

		const entries = {
			(0 .. 1, 14 .. 15, 3, 1 .. 4 , 17): a0();
			(0 .. 1, 14 .. 15, 2, 3, 17): a1();
			(0 .. 7, 14 .. 15, 3, 3, 17): a6();
		}
		default_action = drop();
	}

    apply {
	if (hdr.ipv4.isValid()) {
		//Ignore this, it's basic
		ipv4_lpm.apply();	    	

		//Applying this table will effect the index, leaf, and continue metadata
		root.apply();

		//Only search if continue is set
		if(meta.continue == 1) {
			if (meta.index == 1) { node1.apply();}
			else {NoAction();}
		/*
			There was only one node here but if there was multiple nodes the search would look like this
			else if (meta.index == 2) { node2.apply();}
			else if (meta.index == 3) { node3.apply();}
			else if (meta.index == 4) { node4.apply();}
			else {NoAction();}
		*/
		}

	/*
		Also there was only 1 extra level to search, but if there were more, it would look like this
		if(meta.continue == 1) {
			if (meta.index == 1) { node1.apply();}
			else if (meta.index == 2) { node2.apply();}
			else if (meta.index == 3) { node3.apply();}
			else if (meta.index == 4) { node4.apply();}
			else {NoAction();}
		}
		NOTE: This is pretty much the same code as before and that's okay, as long as internal nodes on 
		the same level of the tree have unique index id's than this process can repeat as many times
		as there are levels in the tree, pretty neat I think
	*/

		//If a rule is matched than that means that the leaf value is non-zero and should match one of the leaves
		if(meta.leaf == 1) {leaf1.apply();}
		else if (meta.leaf == 2) {leaf2.apply();}
		else if (meta.leaf == 3) {leaf3.apply();}
		else if (meta.leaf == 4) {leaf4.apply();}
		else if (meta.leaf == 5) {leaf5.apply();}
		else if (meta.leaf == 6) {leaf6.apply();}
		else if (meta.leaf == 7) {leaf7.apply();}
		else if (meta.leaf == 8) {leaf8.apply();}
		else if (meta.leaf == 9) {leaf9.apply();}
		else {drop();}
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

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 =  0x800;
const bit<16> TYPE_RFM  =  0x801;
const bit<16> TYPE_SR   =  0x700;
const bit<16> TYPE_INT  =  0x701;
const bit<16> TYPE_SW_ADD = 0x702;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<8>  port_t;
typedef bit<9>  egressSpec_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// etherType  0x800: ipv4; 0x801 RFM

header rform_t {
    bit<1>      version;
    bit<7>      taskid;
    bit<16>     bdr;   // Mb bandwidth
    bit<8>      mgi;  // multicast group id
    // bit<8>      hop_cnt;   // 将 hop_cnt 拆成两部分，用来辅助路径收集以及资源回收
    bit<4>      hop_cnt;
    bit<4>      reverse_cnt;
    bit<8>      dst_sw;
    bit<16>     type;  // 0x700:sr; 0x701: int
}

header probe_t {
    bit<8>      hop_cnt;
}

header inthdr_t {
    bit<1>      type;    // for sr the last hop
    bit<7>      rsvd;
    port_t      ingress_port;
    port_t      egress_port;
}

header sr_t {
    bit<1>      type;    // for sr the last hop
    bit<7>      rsvd;
    port_t      ingress_port;
    port_t      egress_port;
}


header sw_t {
    bit<8>      sw_id;
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
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
}

struct headers {
    ethernet_t      ethernet;
    rform_t         rform;
    probe_t         probe;
    inthdr_t[5]     inthdr;
    sr_t[5]         sr;
    sw_t            sw;
    sw_t[5]         swes;
    ipv4_t          ipv4;
    tcp_t           tcp;
}



struct metadata {
    probe_t      probe;
    bit<48>     utilization_bd;
    bit<32>     c;
    bit<1>      has_gone_tor;
    bit<8>      first_sw_id;
    bit<8>      last_sw_id;
    bit<8>      num_has_gone;
    port_t      egress_port;
    bit<2>      switch_type;

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

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4:  parse_ipv4;
            TYPE_RFM:   parse_rfm;
            default:    accept;
        }
    }

    state parse_rfm {
        packet.extract(hdr.rform);
        meta.probe.hop_cnt = (bit<8>)hdr.rform.hop_cnt ;
        transition select(hdr.rform.type){
            TYPE_INT:       parse_probe;
            TYPE_SR:        parse_sr;
            TYPE_SW_ADD:    parse_switches;
        }
    }

    state parse_switches{
        packet.extract(hdr.swes.next);
        meta.num_has_gone = meta.num_has_gone + 1;
        transition select(meta.num_has_gone){
            3:              accept;
            default:        parse_switches;
        }


    }

    state parse_probe {
        packet.extract(hdr.probe);
        transition select(hdr.probe.hop_cnt) {
            0:          accept;
            default:    parse_int_info;
        }
    }



    state parse_int_info {
        packet.extract(hdr.inthdr.next);
        transition select(hdr.inthdr.last.type){
            0:      parse_int_info;
            default:    accept;
        }
    }

    state parse_sr {
        packet.extract(hdr.sr.next);
        transition select(hdr.sr.last.type){
            0:      parse_sr;
            default:    accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

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
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        drop();
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.rform);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.swes);
        packet.emit(hdr.sr);
        packet.emit(hdr.probe);
        packet.emit(hdr.inthdr);
        packet.emit(hdr.sw);
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

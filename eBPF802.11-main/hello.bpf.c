
/*mandatory include*/
#include <linux/types.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>
#include "wifi_packet.h"

/*User define*/
#define MAX_ENTRIES 10240

/*structure for map*/
struct key {
    __u8 address[6];
};

struct value {
    __u64 countBeacon;
    __u64 countProbeReq;
    __u64 countProbeRes;
    __u64 countAssocReq;
    __u64 countAssocRes;
    __u64 countAuth;
    
    __u64 countAck;
    __u64 countRts;
    __u64 countPsPoll;
    __u64 countCts;
    
    __u64 countData;
    __u64 countQosData;
    
    __u64 countUnknown;
    char SSID[33];
};

/*define a BPF_MAP_TYPE_HASH*/
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct key);
 __type(value, struct value);
 __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_map_count1 SEC(".maps");

static int isBeacon(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 26 + 2 > data_end) {
        bpf_printk("ERR: Radio tap has a problem");
        return 0;
    }
    data = data + 26; // pass the Radiotap header (for raspberry 26 -> 18 ?)
    frame_control_t *fcs = (frame_control_t *)data;
    if (data + sizeof(frame_control_t) > data_end) {
        bpf_printk("ERR: frameControl has a problem");
        return 0;
    };
    
    __u16 *frame_control = (__u16 *)data;
    bpf_printk("Frame Control (raw): 0x%04x", *frame_control);
    
    /*Debug purpose*/
    if (fcs->type == 0x00 & fcs->subtype == 0x08) {
        bpf_printk("Found beacon frame");
        return 1;
    }
    return 0;
}

/*get the SSID of the Beacon Frame*/
static int getSSID(struct xdp_md *ctx, char* bufferSSID, int* len) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 26 + 2 > data_end) {
        bpf_printk("ERR: Radio tap has a problem");
        return 1;
    }
    data = data + 26; // bypass the Radiotap header (for raspberry 26 -> 18 ?)
    if (data + 24 > data_end) {
        bpf_printk("ERR: Beacon header has a problem");
        return 1;
    }
    data = data + 24; // bypass the MAC header
    if (data + 12 > data_end) {
        bpf_printk("ERR: First three field of Frame Body has a problem");
        return 1;
    }
    data = data + 12; // bypass the first 3 field of Frame Body
    if (data + sizeof(infoSSID) > data_end) {
        bpf_printk("ERR: SSID has a problem [0]");
        return 1;
    }
    infoSSID *info = (infoSSID*)data;
    /*Get SSID*/
    int lenSSID = info->tagLength;
    *len = lenSSID;
    data = data + sizeof(infoSSID); // Jump to actual SSID
      if (data + 32 > data_end) {
        bpf_printk("ERR: SSID has a problem [1]");
        return 1;
    }
    char *data_mem = (char*)data;
    for (int i = 0; i < 32; i++)
    {
        bufferSSID[i] = data_mem[i];
    }
    return 0;
}

/*update HASH_MAP*/
static int updateAddress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 26 + 2 > data_end) {
        bpf_printk("ERR: checkpoint radio\n");
        return 0;
    }

    /*MAJOR PROBLEM*/
    data = data + 26; 
    frame_control_t *fcs = (frame_control_t *)data;
	if (classify_frame(fcs->type, fcs->subtype) == 16) {
	    rts_poll_header_t *header = (rts_poll_header_t *)data;
	    if (data + sizeof(rts_poll_header_t) > data_end) {
		bpf_printk("ERR: checkpoint header\n");
		return 0;
	    }
	    struct key key;
	    struct value *values;

		/*Second Address*/ /*Source MAC*/
	    key.address[0] = header->addr2[0];
	    key.address[1] = header->addr2[1];
	    key.address[2] = header->addr2[2];
	    key.address[3] = header->addr2[3];
	    key.address[4] = header->addr2[4];
	    key.address[5] = header->addr2[5];
	    values = bpf_map_lookup_elem(&xdp_map_count1, &key);
	    if (values) {
		count_frame(header->frame_control.type, header->frame_control.subtype, (struct val *)values);
		bpf_map_update_elem(&xdp_map_count1, &key, values, BPF_ANY);
	    } else {
		// not capture the first frame
		struct value newval = {}; 
		bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
	    }
	    return XDP_PASS;
	} else if (classify_frame(fcs->type, fcs->subtype) == 10) {
	    cts_ack_header_t *header = (cts_ack_header_t *)data;
	    if (data + sizeof(cts_ack_header_t) > data_end) {
		bpf_printk("ERR: checkpoint header\n");
		return 0;
	    }
	    struct key key;
	    struct value *values;

		/*Second Address*/ /*Source MAC*/
	    key.address[0] = header->addr1[0];
	    key.address[1] = header->addr1[1];
	    key.address[2] = header->addr1[2];
	    key.address[3] = header->addr1[3];
	    key.address[4] = header->addr1[4];
	    key.address[5] = header->addr1[5];
	    values = bpf_map_lookup_elem(&xdp_map_count1, &key);
	    if (values) {
		count_frame(header->frame_control.type, header->frame_control.subtype, (struct val *)values);
		bpf_map_update_elem(&xdp_map_count1, &key, values, BPF_ANY);
	    } else {
		// not capture the first frame
		struct value newval = {}; 
		bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
	    }
	    return XDP_PASS;
	} else if (classify_frame(fcs->type, fcs->subtype) == 34) {
	    data_header_t *header = (data_header_t *)data;
	    if (data + sizeof(data_header_t) > data_end) {
		bpf_printk("ERR: checkpoint header\n");
		return 0;
	    }
	    struct key key;
	    struct value *values;

		/*Second Address*/ /*Source MAC*/
	    key.address[0] = header->addr2[0];
	    key.address[1] = header->addr2[1];
	    key.address[2] = header->addr2[2];
	    key.address[3] = header->addr2[3];
	    key.address[4] = header->addr2[4];
	    key.address[5] = header->addr2[5];
	    values = bpf_map_lookup_elem(&xdp_map_count1, &key);
	    if (values) {
		count_frame(header->frame_control.type, header->frame_control.subtype, (struct val *)values);
		bpf_map_update_elem(&xdp_map_count1, &key, values, BPF_ANY);
	    } else {
		// not capture the first frame
		struct value newval = {}; 
		bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
	    }
	    return XDP_PASS;
	} else if (classify_frame(fcs->type, fcs->subtype) == 36) {
	    qos_data_header_t *header = (qos_data_header_t *)data;
	    if (data + sizeof(qos_data_header_t) > data_end) {
		bpf_printk("ERR: checkpoint header\n");
		return 0;
	    }
	    struct key key;
	    struct value *values;

		/*Second Address*/ /*Source MAC*/
	    key.address[0] = header->addr2[0];
	    key.address[1] = header->addr2[1];
	    key.address[2] = header->addr2[2];
	    key.address[3] = header->addr2[3];
	    key.address[4] = header->addr2[4];
	    key.address[5] = header->addr2[5];
	    values = bpf_map_lookup_elem(&xdp_map_count1, &key);
	    if (values) {
		count_frame(header->frame_control.type, header->frame_control.subtype, (struct val *)values);
		bpf_map_update_elem(&xdp_map_count1, &key, values, BPF_ANY);
	    } else {
		// not capture the first frame
		struct value newval = {}; 
		bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
	    }
	    return XDP_PASS;
	} else {
	    mana_header_t *header = (mana_header_t *)data;
	    if (data + sizeof(mana_header_t) > data_end) {
		bpf_printk("ERR: checkpoint header\n");
		return 0;
	    }


	    struct key key;
	    struct value *values;

		/*Second Address*/ /*Source MAC*/
	    key.address[0] = header->addr2[0];
	    key.address[1] = header->addr2[1];
	    key.address[2] = header->addr2[2];
	    key.address[3] = header->addr2[3];
	    key.address[4] = header->addr2[4];
	    key.address[5] = header->addr2[5];
	    values = bpf_map_lookup_elem(&xdp_map_count1, &key);
	    if (values) {
		count_frame(header->frame_control.type, header->frame_control.subtype, (struct val *)values);
		
		if (isBeacon(ctx))
		{
		    char SSID[33] = "asvabsews";
		    int len = 0;
		    getSSID(ctx,SSID,&len);
		    if (len<sizeof(SSID))
		    {
		    SSID[len] = '\0'; // NULL terminator
		    }
		    // fuck you LLVM
		    values->SSID[0] = SSID[0];
		    values->SSID[1] = SSID[1];
		    values->SSID[2] = SSID[2];
		    values->SSID[3] = SSID[3];
		    values->SSID[4] = SSID[4];
		    values->SSID[5] = SSID[5];
		    values->SSID[6] = SSID[6];
		    values->SSID[7] = SSID[7];
		    values->SSID[8] = SSID[8];
		    values->SSID[9] = SSID[9];
		    values->SSID[10] = SSID[10];
		    values->SSID[11] = SSID[11];
		    values->SSID[12] = SSID[12];
		    values->SSID[13] = SSID[13];
		    values->SSID[14] = SSID[14];
		    values->SSID[15] = SSID[15];
		    values->SSID[16] = SSID[16];
		    values->SSID[17] = SSID[17];
		    values->SSID[18] = SSID[18];
		    values->SSID[19] = SSID[19];
		    values->SSID[20] = SSID[20];
		    values->SSID[21] = SSID[21];
		    values->SSID[22] = SSID[22];
		    values->SSID[23] = SSID[23];
		    values->SSID[24] = SSID[24];
		    values->SSID[25] = SSID[25];
		    values->SSID[26] = SSID[26];
		    values->SSID[27] = SSID[27];
		    values->SSID[28] = SSID[28];
		    values->SSID[29] = SSID[29];
		    values->SSID[30] = SSID[30];
		    values->SSID[31] = SSID[31];
		    values->SSID[32] = '\0';
		    bpf_printk("SSID is %s",values->SSID);
		}
		
		bpf_map_update_elem(&xdp_map_count1, &key, values, BPF_ANY);
	    } else {
		// not capture the first frame
		struct value newval = {}; 
		bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
	    }
	    return XDP_PASS;
	}
	return XDP_PASS;
}

SEC("xdp")
int ping(struct xdp_md *ctx) {
    updateAddress(ctx);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

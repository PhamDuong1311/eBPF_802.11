#ifndef WIFI_PACKET_H
#define WIFI_PACKET_H

#include <linux/types.h>

struct radiotapHeader {
	__u8 length[26];
};

typedef struct {
    __u8 tagNumber;
    __u8 tagLength;
} infoSSID;

/*structure for FCS*/

typedef struct {
    __u16 version: 2;      
    __u16 type: 2;         
    __u16 subtype: 4;      
    __u16 toDs: 1;         
    __u16 fromDs: 1;       
    __u16 moreFrag: 1;     
    __u16 retry: 1;        
    __u16 pwrMgt: 1;       
    __u16 moreData: 1;     
    __u16 wep: 1;         
    __u16 order: 1;       
} frame_control_t;

typedef struct {
	frame_control_t frame_control;
	__u8 duration[2];
	__u8 addr1[6];
	__u8 addr2[6];
	__u8 addr3[6];
	__u8 sequence_control[2];
} mana_header_t;

typedef struct {
	frame_control_t frame_control;
	__u8 duration[2];
	__u8 addr1[6];
	__u8 addr2[6];
} rts_poll_header_t;

typedef struct {
	frame_control_t frame_control;
	__u8 duration[2];
	__u8 addr1[6];
} cts_ack_header_t;

typedef struct {
	frame_control_t frame_control;
	__u8 duration[2];
	__u8 addr1[6];
	__u8 addr2[6];
	__u8 addr3[6];
	__u8 sequence_control[2];
	__u8 addr4[6];
	__u8 qos[2];
	__u8 ht_control[4];

} qos_data_header_t;

typedef struct {
	frame_control_t frame_control;
	__u8 duration[2];
	__u8 addr1[6];
	__u8 addr2[6];
	__u8 addr3[6];
	__u8 sequence_control[2];
	__u8 addr4[6];
	__u8 ht_control[4];
} data_header_t;

struct val {
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


int classify_frame(__u8 type, __u16 subtype) {
    if (type == 0x00) { // Management frame
	return 24;
    } else if (type == 0x01) { // Control frame
        switch (subtype) {
            case 0x0A: 
		return 16;
            case 0x0B: 
		return 16;
            case 0x0C: 
		return 10;
            case 0x0D: 
		return 10;
            default: 
		return 24;
        }
    } else if (type == 0x02) { // Data frame
	switch (subtype) {
	    case 0x00:
	    	return 34;
	    case 0x08:
	    	return 36;
	    default:
	    	return 24;
	}
    } return 24;
 
}

void count_frame(__u8 type, __u16 subtype, struct val *val) {
    if (type == 0x00) { // Management frame
        switch (subtype) {
            case 0x00: 
                val->countAssocReq++;
                break;
            case 0x01: 
                val->countAssocRes++;
                break;
            case 0x04: 
                val->countProbeReq++;
                break;
            case 0x05: 
                val->countProbeRes++;
                break;
            case 0x08: 
                val->countBeacon++;
                break;
            case 0x0B: 
                val->countAuth++;
                break;
            default: 
                val->countUnknown++;
                break;
        }
    } else if (type == 0x01) { // Control frame
        switch (subtype) {
            case 0x0A: 
                val->countPsPoll++;
                break;
            case 0x0B: 
                val->countRts++;
                break;
            case 0x0C: 
                val->countCts++;
                break;
            case 0x0D: 
                val->countAck++;
                break;
            default: 
                val->countUnknown++;
                break;
        }
    } else if (type == 0x02) { // Data frame
        switch (subtype) {
            case 0x00: 
                val->countData++;
                break;
            case 0x08: 
                val->countQosData++;
                break;
            default: 
                val->countUnknown++;
                break;
        }
    } else {
        val->countUnknown++;
    }
}



#endif


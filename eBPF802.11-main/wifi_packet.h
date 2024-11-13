#ifndef WIFI_PACKET_H
#define WIFI_PACKET_H

#include <linux/types.h>

struct radiotapHeader {
    __u8 rev;
    __u8 pad;
    __u8 length_1;
    __u8 length_2;
    __u32 presentFlags;
    __u8 flag;
    __u8 datarate;
    __u16 frequency;
    __u16 channelFlags;
    __u8 s2complementSignal;
    __u8 atena;
    __u16 rxFlags;
    __u16 rxFlags1;
};
typedef struct {
    __u8 timeStamp[8];
    __u8 beaconInterval[2];
    __u8 capabilityInfo[2];
} firstThreeField;

typedef struct {
    __u8 tagNumber;
    __u8 tagLength;
} infoSSID;

/*structure for FCS*/
struct frameControl {
    __u8 fcs[2];
};
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
	__u8 addr4[6];
} wifi_header_t;

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

void classify_subtype(__u8 type, __u16 subtype, struct val *val) {
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


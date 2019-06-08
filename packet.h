#pragma once

typedef enum {
    TEST = 0,

    SendNetBufferListsHandler,
    SendNetBufferListsCompleteHandler,

    ReceiveNetBufferListsHandler,//这个暂时没有使用。
    ReturnNetBufferListsHandler,

    //

} SendORReceive;


/*
PARP_HEADER结构没有定义完毕的补充。
没有定义，可能是PARP_HEADER指定了后续的大小，这些大小可能是会改变的。

1.结构的名字可以改为：ARP_BODY，与PARP_HEADER相对应。
2.另一个是重新定义PARP_HEADER，把原来的系统的定义给覆盖掉。
#ifdef PARP_HEADER
    XXXXXX    
#endif
*/
#pragma pack(push, 1) //导致RtlIpv4AddressToString警告。
typedef struct _ARP_MAC_IP {
    DL_EUI48 SenderHardwareAddress;//UINT8    SenderHardwareAddress[6];//DL_EUI48 SenderHardwareAddress;
    IN_ADDR  SenderProtocolAddress;    
    DL_EUI48 TargetHardwareAddress;//UINT8    TargetHardwareAddress[6];//DL_EUI48 TargetHardwareAddress;
    IN_ADDR  TargetProtocolAddress;
} ARP_MAC_IP, *PARP_MAC_IP;
#pragma pack(pop)


/*
Define the UDP header 
搜遍了整个WDK没有发现UDP的结构的定义。
这个结构摘自：SDK的PING源码。
*/
typedef struct udp_hdr {
    unsigned short src_portno;       // Source port no.
    unsigned short dst_portno;       // Dest. port no.
    unsigned short udp_length;       // Udp packet length
    unsigned short udp_checksum;     // Udp checksum (optional)
} UDP_HDR, *PUDP_HDR;



VOID get_packet(PNET_BUFFER_LIST CurrNbl, SendORReceive Send_Receive);
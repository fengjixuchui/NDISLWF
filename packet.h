#pragma once

typedef enum {
    TEST = 0,

    SendNetBufferListsHandler,
    SendNetBufferListsCompleteHandler,

    ReceiveNetBufferListsHandler,//�����ʱû��ʹ�á�
    ReturnNetBufferListsHandler,

    //

} SendORReceive;


/*
PARP_HEADER�ṹû�ж�����ϵĲ��䡣
û�ж��壬������PARP_HEADERָ���˺����Ĵ�С����Щ��С�����ǻ�ı�ġ�

1.�ṹ�����ֿ��Ը�Ϊ��ARP_BODY����PARP_HEADER���Ӧ��
2.��һ�������¶���PARP_HEADER����ԭ����ϵͳ�Ķ�������ǵ���
#ifdef PARP_HEADER
    XXXXXX    
#endif
*/
#pragma pack(push, 1) //����RtlIpv4AddressToString���档
typedef struct _ARP_MAC_IP {
    DL_EUI48 SenderHardwareAddress;//UINT8    SenderHardwareAddress[6];//DL_EUI48 SenderHardwareAddress;
    IN_ADDR  SenderProtocolAddress;    
    DL_EUI48 TargetHardwareAddress;//UINT8    TargetHardwareAddress[6];//DL_EUI48 TargetHardwareAddress;
    IN_ADDR  TargetProtocolAddress;
} ARP_MAC_IP, *PARP_MAC_IP;
#pragma pack(pop)


/*
Define the UDP header 
�ѱ�������WDKû�з���UDP�Ľṹ�Ķ��塣
����ṹժ�ԣ�SDK��PINGԴ�롣
*/
typedef struct udp_hdr {
    unsigned short src_portno;       // Source port no.
    unsigned short dst_portno;       // Dest. port no.
    unsigned short udp_length;       // Udp packet length
    unsigned short udp_checksum;     // Udp checksum (optional)
} UDP_HDR, *PUDP_HDR;



VOID get_packet(PNET_BUFFER_LIST CurrNbl, SendORReceive Send_Receive);
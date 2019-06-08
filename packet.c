#include  "precomp.h"

#pragma warning(disable:4189) //局部变量已初始化但不引用


VOID Analytical_ipv4_tcp_http_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PETHERNET_HEADER peh = packet;
    PIPV4_HEADER ipv4 = (PIPV4_HEADER)((PBYTE)packet + ETH_LENGTH_OF_HEADER);
    PTCP_HDR tcp = (PTCP_HDR)((PBYTE)ipv4 + Ip4HeaderLengthInBytes(ipv4));
    char * http = (char *)tcp + (tcp->th_len * (32 / 8));
    char src_ipv4[32] = {0};//This buffer should be large enough to hold at least 16 characters.
    char dest_ipv4[32] = {0};
    UINT16 Source_port = RtlUshortByteSwap(tcp->th_sport);
    UINT16 Destination_port = RtlUshortByteSwap(tcp->th_dport);

    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive);

    RtlIpv4AddressToString(&ipv4->SourceAddress, src_ipv4);
    RtlIpv4AddressToString(&ipv4->DestinationAddress, dest_ipv4);

    //KdPrint(("http(Send_Receive) : Destination MAC:%02X%02X%02X%02X%02X%02X,Source MAC:%02X%02X%02X%02X%02X%02X,Source IP:%s,Destination IP:%s,Source port:%d,Destination port:%d, http:0x%p, toutal data length:%d\n",
    //    peh->Destination.Byte[0],peh->Destination.Byte[1],peh->Destination.Byte[2],peh->Destination.Byte[3],peh->Destination.Byte[4],peh->Destination.Byte[5],
    //    peh->Source.Byte[0],peh->Source.Byte[1],peh->Source.Byte[2],peh->Source.Byte[3],peh->Source.Byte[4],peh->Source.Byte[5],
    //    src_ipv4, 
    //    dest_ipv4, 
    //    Source_port,
    //    Destination_port,
    //    http,
    //    Length));

    /*
    识别HTTP的连接和断开与收发消息的区别：
    ACK一定为1  TH_ACK
    PSH %95为1
    tcp->th_len大多为20.
    准确的还是识别那些字吧！
    GET
    HEAD
    POST
    PUT
    DELETE
    TRACE
    CONNECT
    extension-method = token  LOCK MKCOL COPY MOVE

    HTTP
    注意大小写。
    */
    {
        ANSI_STRING as_HTTP = RTL_CONSTANT_STRING("HTTP");
        ANSI_STRING GET = RTL_CONSTANT_STRING("GET");
        ANSI_STRING POST = RTL_CONSTANT_STRING("POST");
        //ANSI_STRING HEAD = RTL_CONSTANT_STRING("HEAD");
        //ANSI_STRING PUT = RTL_CONSTANT_STRING("PUT");
        //ANSI_STRING DELETE_ = RTL_CONSTANT_STRING("DELETE");
        //ANSI_STRING TRACE = RTL_CONSTANT_STRING("TRACE");
        //ANSI_STRING CONNECT = RTL_CONSTANT_STRING("CONNECT");

        ANSI_STRING test = {0};
        test.Buffer = http;
        test.MaximumLength = 9;//其实和指定更多，只要不越界。

        test.Length = as_HTTP.Length;
        if (RtlCompareString(&as_HTTP, &test, TRUE) == 0)
        {
            KdPrint(("%s\n", http));
            return;
        }

        test.Length = GET.Length;
        if (RtlCompareString(&GET, &test, TRUE) == 0)
        {
            KdPrint(("%s\n", http));
            return;
        }

        test.Length = POST.Length;
        if (RtlCompareString(&POST, &test, TRUE) == 0)
        {
            KdPrint(("%s\n", http));
            return;
        }

        //还可以分析其他。

    }
}


VOID Analytical_ipv4_tcp_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PIPV4_HEADER ipv4 = (PIPV4_HEADER)((PBYTE)packet + ETH_LENGTH_OF_HEADER);
    PTCP_HDR tcp = (PTCP_HDR)((PBYTE)ipv4 + Ip4HeaderLengthInBytes(ipv4));
    UINT16 Source_port = RtlUshortByteSwap(tcp->th_sport);
    UINT16 Destination_port = RtlUshortByteSwap(tcp->th_dport);
    
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive);

    /*
    1.TH_MAX_LEN >= (tcp->th_len * (32 / 8)) >= sizeof(TCP_HDR).
    2.#define TH_MAX_LEN  (0x0F << 2) == 60 //Define the maximum length of a TCP header with options.
    3.tcp->th_len * (32 / 8) 一般等于 20 但大于20的也时常发生。
    4.sizeof(TCP_HDR) == 20
    5.tcp->th_len * (32 / 8) - sizeof(TCP_HDR) == TCP的选项的大小。
    */
    if (tcp->th_len * (32 / 8) - sizeof(TCP_HDR))
    {
        KdPrint(("\nIPV4的TCP的选项的大小:%X\n\n", tcp->th_len * (32 / 8) - sizeof(TCP_HDR)));
    }

    switch(Source_port) 
    {
    case 80://http
        Analytical_ipv4_tcp_http_packet(packet, Length, Send_Receive);
        break;
    case IPPORT_HTTPS:
        NOTHING ;
        break;   
    default:
        NOTHING ;
        break;
    }

    switch(Destination_port) 
    {
    case 80://http
        Analytical_ipv4_tcp_http_packet(packet, Length, Send_Receive);
        break;
    case IPPORT_HTTPS:
        NOTHING ;
        break;   
    default:
        NOTHING ;
        break;
    }
}


VOID Analytical_ipv4_udp_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PIPV4_HEADER ipv4 = (PIPV4_HEADER)((PBYTE)packet + ETH_LENGTH_OF_HEADER);
    PUDP_HDR udp = (PUDP_HDR)((PBYTE)ipv4 + Ip4HeaderLengthInBytes(ipv4));
    UINT16 Source_port = RtlUshortByteSwap(udp->src_portno);
    UINT16 Destination_port = RtlUshortByteSwap(udp->dst_portno);
    
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive);

    /*
    端口信息参考：http://support.microsoft.com/kb/136403/zh-cn 
    可以在WDK的里面搜索下有这些定义/声明没.
    */
    switch(Source_port) 
    {
    case IPPORT_NETSTAT://What is the network status
        NOTHING ;
        break;
    case 53://DOMAIN      Domain Name Server
        NOTHING ;
        break;   
    case IPPORT_TFTP://Trivial File Transfer Protocol
        NOTHING ;
        break;
    case IPPORT_NETBIOS_NS://NetBIOS name service
        NOTHING ;
        break;   
    case IPPORT_NETBIOS_DGM://NetBIOS datagram service
        NOTHING ;
        break;
    case IPPORT_SNMP://SNMP network monitor    
        NOTHING ;
        break;   
    default:
        NOTHING ;
        break;
    }

    switch(Destination_port) 
    {
    case IPPORT_NETSTAT://What is the network status
        NOTHING ;
        break;
    case 53://DOMAIN      Domain Name Server
        NOTHING ;
        break;   
    case IPPORT_TFTP://Trivial File Transfer Protocol
        NOTHING ;
        break;
    case IPPORT_NETBIOS_NS://NetBIOS name service
        NOTHING ;
        break;   
    case IPPORT_NETBIOS_DGM://NetBIOS datagram service
        NOTHING ;
        break;
    case IPPORT_SNMP://SNMP network monitor    
        NOTHING ;
        break;   
    default:
        NOTHING ;
        break;
    }
}


VOID Analytical_ipv4_igmp_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PIPV4_HEADER ipv4 = (PIPV4_HEADER)((PBYTE)packet + ETH_LENGTH_OF_HEADER);
    PIGMP_HEADER pigmpv4_m = (PIGMP_HEADER)((PBYTE)ipv4 + Ip4HeaderLengthInBytes(ipv4));//PICMPV4_MESSAGE == PICMPV6_MESSAGE
    UINT8 Version = pigmpv4_m->Version;
    UINT8 Type = pigmpv4_m->Type; 
    int igmp_length = Length - ETH_LENGTH_OF_HEADER - Ip4HeaderLengthInBytes(ipv4);
    
    UNREFERENCED_PARAMETER(Send_Receive); 

    /*
    经测试发现：Version == 2时，大小是16字节。
    */
    if (sizeof(IGMP_HEADER) != igmp_length)
    {
        KdPrint(("\nIPV4的IGMP_HEADER大小:%X,不等于8字节。\n", igmp_length));
    }

    switch(Version) 
    {
    case 1:
        switch(Type) 
        {
        case 1://IGMP类型为1说明是由多播路由器发出的查询报文

            break; 
        case 2://为2说明是主机发出的报告报文.

            break; 
        default:
            KdBreakPoint();
            break;  
        }
        break; 
    case 2:
        switch(Type) 
        {
        case 1://IGMP类型为1说明是由多播路由器发出的查询报文
            KdPrint(("\nIPV4的IGMP版本为2的：多播路由器发出的查询报文。\n"));//格式有待查询和研究。
            break; 
        case 2://为2说明是主机发出的报告报文.
            KdPrint(("\nIPV4的IGMP版本为2的：主机发出的报告报文。\n"));//格式有待查询和研究。
            break; 
        default:
            KdBreakPoint();
            break;  
        }
        break; 
    default:
        KdPrint(("\nIPV4的IGMP版本为：%d\n", Version));
        break;  
    }
}


VOID Analytical_ipv4_icmp_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PIPV4_HEADER ipv4 = (PIPV4_HEADER)((PBYTE)packet + ETH_LENGTH_OF_HEADER);
    PICMPV4_MESSAGE picmpv4_m = (PICMPV4_MESSAGE)((PBYTE)ipv4 + Ip4HeaderLengthInBytes(ipv4));//PICMPV4_MESSAGE == PICMPV6_MESSAGE
    UINT8 Type = picmpv4_m->Header.Type;
    UINT8 Code = picmpv4_m->Header.Code;
    
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive);

    switch(Type) 
    {
    case ICMP4_ECHO_REPLY:
        KdPrint(("\nipv4_icmp:ICMP4_ECHO_REPLY\n"));
        break;
    case ICMP4_DST_UNREACH:
        switch(Code) 
        {
        case ICMP4_UNREACH_NET:
            NOTHING ;
            break;
        case ICMP4_UNREACH_HOST:
            NOTHING ;
            break;   
        case ICMP4_UNREACH_PROTOCOL:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_PORT:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_FRAG_NEEDED:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_SOURCEROUTE_FAILED:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_NET_UNKNOWN:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_HOST_UNKNOWN:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_ISOLATED:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_NET_ADMIN:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_HOST_ADMIN:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_NET_TOS:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_HOST_TOS:
            NOTHING ;
            break; 
        case ICMP4_UNREACH_ADMIN:
            NOTHING ;
            break; 
        default:
            NOTHING ;
            break;
        }
        break;   
    case ICMP4_SOURCE_QUENCH:
        NOTHING ;
        break;
    case ICMP4_REDIRECT:
        NOTHING ;
        break;
    case ICMP4_ECHO_REQUEST:
        KdPrint(("\nipv4_icmp:ICMP4_ECHO_REQUEST\n"));
        break;
    case ICMP4_ROUTER_ADVERT:
        NOTHING ;
        break;
    case ICMP4_ROUTER_SOLICIT:
        NOTHING ;
        break;
    case ICMP4_TIME_EXCEEDED:
        NOTHING ;
        break;
    case ICMP4_PARAM_PROB:
        NOTHING ;
        break;
    case ICMP4_TIMESTAMP_REQUEST:
        NOTHING ;
        break;
    case ICMP4_TIMESTAMP_REPLY:
        NOTHING ;
        break;
    case ICMP4_MASK_REQUEST:
        NOTHING ;
        break;
    case ICMP4_MASK_REPLY:
        NOTHING ;
        break;
    default:
        NOTHING ;
        break;
    }
}


VOID Analytical_ipv4_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PIPV4_HEADER ipv4 = (PIPV4_HEADER)((PBYTE)packet + ETH_LENGTH_OF_HEADER);
    
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive); 

    /*
    1.MAX_IPV4_HLEN >= Ip4HeaderLengthInBytes(ipv4) >= sizeof(IPV4_HEADER).
    2.MAX_IPV4_HLEN == 60 == 0x0f * (32/8)
    3.Ip4HeaderLengthInBytes(ipv4) == 5 * 4 == 20
    4.C_ASSERT(sizeof(IPV4_HEADER) == 20)
    5.Ip4HeaderLengthInBytes(ipv4) - sizeof(IPV4_HEADER) == IPV4的选项的大小。
    6.MAX_IP_OPTIONS_LENGTH  ==  ((0xF * sizeof(UINT32)) - sizeof(IPV4_HEADER))
    */
    if (Ip4HeaderLengthInBytes(ipv4) - sizeof(IPV4_HEADER))
    {
        PIPV4_OPTION_HEADER pipv4_o_h = (PIPV4_OPTION_HEADER)((PBYTE)ipv4 + sizeof(IPV4_HEADER));//可进行进一步的分析。
        KdPrint(("\nIPV4的选项的大小:%X，OptionType：0X%X\n\n", Ip4HeaderLengthInBytes(ipv4) - sizeof(IPV4_HEADER), pipv4_o_h->OptionType));

        switch(pipv4_o_h->OptionType) 
        {
        case IP_OPT_EOL:
            NOTHING ;
            break;
        case IP_OPT_NOP:
            NOTHING ;
            break;
        case IP_OPT_SECURITY:
            NOTHING ;
            break;
        case IP_OPT_LSRR:
            NOTHING ;
            break;  
        case IP_OPT_TS:
            NOTHING ;
            break;
        case IP_OPT_RR:
            NOTHING ;
            break;
        case IP_OPT_SSRR:
            NOTHING ;
            break;
        case IP_OPT_SID:
            NOTHING ;
            break; 
        case IP_OPT_ROUTER_ALERT:
            NOTHING ;
            break;
        case IP_OPT_MULTIDEST:
            NOTHING ;
            break;
        default:
            NOTHING ;
            break;  
        }
    }

    switch(ipv4->Protocol) 
    {
    case IPPROTO_ICMP://虽然是IPV6的定义，但是和IPV4的一样。
        Analytical_ipv4_icmp_packet(packet, Length, Send_Receive);
        break;
    case IPPROTO_IGMP:
        Analytical_ipv4_igmp_packet(packet, Length, Send_Receive);
        break;
    case IPPROTO_TCP:
        Analytical_ipv4_tcp_packet(packet, Length, Send_Receive);
        break;
    case IPPROTO_UDP:
        Analytical_ipv4_udp_packet(packet, Length, Send_Receive);
        break;    
    default:
        NOTHING ;
        break;  
    }
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


VOID Analytical_ip_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    //BYTE version = PVOID packet[0x0e];
    //version = version & 0xf0;
    //version = version >> 4;

    PIPV4_HEADER ipv4 = (PIPV4_HEADER)((PBYTE)packet + ETH_LENGTH_OF_HEADER);
    BYTE version = ipv4->Version;

    if (version == IPV4_VERSION)
    {
        Analytical_ipv4_packet(packet, Length, Send_Receive);
    }
    else //IPV6?  IPV6_VERSION
    {
        KdBreakPoint(); 
    }
}


VOID Analytical_arp_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PETHERNET_HEADER peh = (PETHERNET_HEADER)packet;
    PARP_HEADER arp = (PARP_HEADER)((PBYTE)peh + ETH_LENGTH_OF_HEADER);
    PARP_MAC_IP ami = (PARP_MAC_IP)((PBYTE)arp + sizeof(ARP_HEADER));
    BYTE broadcast[6] = EUI48_BROADCAST_INIT;

    USHORT Opcode = RtlUshortByteSwap(arp->Opcode);
    USHORT HardwareAddressSpace = RtlUshortByteSwap(arp->HardwareAddressSpace);

    if (RtlCompareMemory(&peh->Destination, &broadcast, sizeof(peh->Destination)) == sizeof(peh->Destination))
    {
        KdPrint(("\nARP的广播报文，就不分析了。\n"));
        return;
    }

    if (arp->HardwareAddressLength != 6)
    {
        KdPrint(("\n发现ARP报文的MAC地址的长度不为6字节。\n"));
    }

    if (arp->ProtocolAddressLength != 4)//IPV4_VERSION
    {
        KdPrint(("\n发现ARP报文的IP的长度不为4字节。\n"));
    }
    
    switch(Opcode)
    {  
    case ARP_REQUEST:
        switch(HardwareAddressSpace)
        {  
        case ARP_HW_ENET:
            if (arp->ProtocolAddressSpace == RtlUshortByteSwap(ETHERNET_TYPE_IPV4)) 
            {  
                char src_ipv4[32] = {0};//This buffer should be large enough to hold at least 16 characters.
                char dest_ipv4[32] = {0};

                RtlIpv4AddressToString((const IN_ADDR *)&ami->SenderProtocolAddress, src_ipv4);//warning C4366: 一元“&”运算符的结果可能是未对齐的。内存对齐指令导致的。
                RtlIpv4AddressToString(&ami->TargetProtocolAddress, dest_ipv4);

                KdPrint(("ARP_REQUEST_ENET_IP : Sender MAC:%02X%02X%02X%02X%02X%02X,Target MAC:%02X%02X%02X%02X%02X%02X,Sender IP:%s,Target IP:%s\n",                    
                    ami->SenderHardwareAddress.Byte[0],
                    ami->SenderHardwareAddress.Byte[1], 
                    ami->SenderHardwareAddress.Byte[2], 
                    ami->SenderHardwareAddress.Byte[3], 
                    ami->SenderHardwareAddress.Byte[4], 
                    ami->SenderHardwareAddress.Byte[5],
                    ami->TargetHardwareAddress.Byte[0], 
                    ami->TargetHardwareAddress.Byte[1],
                    ami->TargetHardwareAddress.Byte[2],
                    ami->TargetHardwareAddress.Byte[3],
                    ami->TargetHardwareAddress.Byte[4],
                    ami->TargetHardwareAddress.Byte[5],
                    src_ipv4, 
                    dest_ipv4));                

                /*
                注意：peh->Destination == EUI48_BROADCAST_INIT 是广播。
                */
            } 
            else 
            {
                KdBreakPoint();  
            }
            break;   
        case ARP_HW_802:
            NOTHING;
            break;
        default:
            KdBreakPoint();  
            break;
        }
        break;   
    case ARP_RESPONSE:
        NOTHING
        break;
    default:
        KdBreakPoint();  
        break;
    }

    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive);
}


VOID Analytical_ipv6_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PETHERNET_HEADER peh = (PETHERNET_HEADER)packet;
    PIPV6_HEADER p_ipv6 = (PIPV6_HEADER)((PBYTE)peh + ETH_LENGTH_OF_HEADER);
    char source_ipv6[64] = {0};// This buffer should be large enough to hold at least 46 characters.
    char destination_ipv6[64] = {0};

    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive);

    RtlIpv6AddressToString(&p_ipv6->SourceAddress, source_ipv6);
    RtlIpv6AddressToString(&p_ipv6->DestinationAddress, destination_ipv6);

    if (p_ipv6->VersionClassFlow != IPV6_VERSION)
    {
        KdPrint(("\n发现：p_ipv6->VersionClassFlow != IPV6_VERSION，而是等于：0X%X。\n", p_ipv6->VersionClassFlow));
    }

    KdPrint(("IPV6:Destination MAC:%02X%02X%02X%02X%02X%02X,Source MAC:%02X%02X%02X%02X%02X%02X,Source IP:%s,Destination IP:%s\n",
        peh->Destination.Byte[0],peh->Destination.Byte[1],peh->Destination.Byte[2],peh->Destination.Byte[3],peh->Destination.Byte[4],peh->Destination.Byte[5],
        peh->Source.Byte[0],peh->Source.Byte[1],peh->Source.Byte[2],peh->Source.Byte[3],peh->Source.Byte[4],peh->Source.Byte[5],
        source_ipv6, 
        destination_ipv6));    

    /*
    具体的有待进一步深入分析。
    */
}


VOID Analytical_802_1Q_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    UNREFERENCED_PARAMETER(packet);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Send_Receive);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


VOID Analytical_packet(PVOID packet, UINT Length, SendORReceive Send_Receive)
{
    PETHERNET_HEADER peh = packet;//应该这个结构可以识别非以太网包。

    if(peh->Type == RtlUshortByteSwap(ETHERNET_TYPE_IPV4) ) 
    {	
        Analytical_ip_packet(packet, Length, Send_Receive);
    }
    else if(peh->Type == RtlUshortByteSwap(ETHERNET_TYPE_ARP)) //RARP也在这里。8035
    {
        Analytical_arp_packet(packet, Length, Send_Receive);
    }
    else if(peh->Type == RtlUshortByteSwap(ETHERNET_TYPE_IPV6)) 
    {
        Analytical_ipv6_packet(packet, Length, Send_Receive);
    }
    else if(peh->Type == RtlUshortByteSwap(ETHERNET_TYPE_802_1Q)) 
    {
        Analytical_802_1Q_packet(packet, Length, Send_Receive);
    }
    else
    {
        /*
        摘自：TCPIP详解卷一的第二章：
        幸运的是， 802定义的有效长度值与以太网的有效类型值无一相同，这样，就可以对两种帧格式进行区分。
        经测试，这里发现的值有：0XCC88，0XA788
        */
        DbgPrint("\n发送其他格式的包Length : 0X%X，可能就不是以太网包了。\n", peh->Type);
    }
}


VOID get_packet(PNET_BUFFER_LIST CurrNbl, SendORReceive Send_Receive)
{
    PNET_BUFFER FirstNetBuffer;
    for(FirstNetBuffer = NET_BUFFER_LIST_FIRST_NB(CurrNbl);  FirstNetBuffer != NULL; FirstNetBuffer = NET_BUFFER_NEXT_NB(FirstNetBuffer))   
    {
        PMDL CurrentMdl = NET_BUFFER_CURRENT_MDL(FirstNetBuffer);
        PVOID VirtualAddress = 0;
        UINT Length = 0;
        PVOID packet = 0;
        ULONG CurrentMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(FirstNetBuffer);

        NdisQueryMdl(CurrentMdl, &VirtualAddress, &Length, NormalPagePriority);//获取虚拟地址和大小。

        packet = VirtualAddress;

        if (CurrentMdlOffset != 0)
        {
            packet = (char *)packet + CurrentMdlOffset;
            Length -= CurrentMdlOffset;            
        }

        //safe_DbgPrint((PUCHAR)(packet), (ULONG)Length);//(ULONG)(Length)//这里的IRQL过高，不宜打印信息，一个思路是降低IRQL或者工作线程。

        Analytical_packet(packet, Length, Send_Receive);
    }
}
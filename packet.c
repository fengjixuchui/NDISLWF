#include  "precomp.h"

#pragma warning(disable:4189) //�ֲ������ѳ�ʼ����������


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
    ʶ��HTTP�����ӺͶϿ����շ���Ϣ������
    ACKһ��Ϊ1  TH_ACK
    PSH %95Ϊ1
    tcp->th_len���Ϊ20.
    ׼ȷ�Ļ���ʶ����Щ�ְɣ�
    GET
    HEAD
    POST
    PUT
    DELETE
    TRACE
    CONNECT
    extension-method = token  LOCK MKCOL COPY MOVE

    HTTP
    ע���Сд��
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
        test.MaximumLength = 9;//��ʵ��ָ�����ֻ࣬Ҫ��Խ�硣

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

        //�����Է���������

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
    3.tcp->th_len * (32 / 8) һ����� 20 ������20��Ҳʱ��������
    4.sizeof(TCP_HDR) == 20
    5.tcp->th_len * (32 / 8) - sizeof(TCP_HDR) == TCP��ѡ��Ĵ�С��
    */
    if (tcp->th_len * (32 / 8) - sizeof(TCP_HDR))
    {
        KdPrint(("\nIPV4��TCP��ѡ��Ĵ�С:%X\n\n", tcp->th_len * (32 / 8) - sizeof(TCP_HDR)));
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
    �˿���Ϣ�ο���http://support.microsoft.com/kb/136403/zh-cn 
    ������WDK����������������Щ����/����û.
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
    �����Է��֣�Version == 2ʱ����С��16�ֽڡ�
    */
    if (sizeof(IGMP_HEADER) != igmp_length)
    {
        KdPrint(("\nIPV4��IGMP_HEADER��С:%X,������8�ֽڡ�\n", igmp_length));
    }

    switch(Version) 
    {
    case 1:
        switch(Type) 
        {
        case 1://IGMP����Ϊ1˵�����ɶಥ·���������Ĳ�ѯ����

            break; 
        case 2://Ϊ2˵�������������ı��汨��.

            break; 
        default:
            KdBreakPoint();
            break;  
        }
        break; 
    case 2:
        switch(Type) 
        {
        case 1://IGMP����Ϊ1˵�����ɶಥ·���������Ĳ�ѯ����
            KdPrint(("\nIPV4��IGMP�汾Ϊ2�ģ��ಥ·���������Ĳ�ѯ���ġ�\n"));//��ʽ�д���ѯ���о���
            break; 
        case 2://Ϊ2˵�������������ı��汨��.
            KdPrint(("\nIPV4��IGMP�汾Ϊ2�ģ����������ı��汨�ġ�\n"));//��ʽ�д���ѯ���о���
            break; 
        default:
            KdBreakPoint();
            break;  
        }
        break; 
    default:
        KdPrint(("\nIPV4��IGMP�汾Ϊ��%d\n", Version));
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
    5.Ip4HeaderLengthInBytes(ipv4) - sizeof(IPV4_HEADER) == IPV4��ѡ��Ĵ�С��
    6.MAX_IP_OPTIONS_LENGTH  ==  ((0xF * sizeof(UINT32)) - sizeof(IPV4_HEADER))
    */
    if (Ip4HeaderLengthInBytes(ipv4) - sizeof(IPV4_HEADER))
    {
        PIPV4_OPTION_HEADER pipv4_o_h = (PIPV4_OPTION_HEADER)((PBYTE)ipv4 + sizeof(IPV4_HEADER));//�ɽ��н�һ���ķ�����
        KdPrint(("\nIPV4��ѡ��Ĵ�С:%X��OptionType��0X%X\n\n", Ip4HeaderLengthInBytes(ipv4) - sizeof(IPV4_HEADER), pipv4_o_h->OptionType));

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
    case IPPROTO_ICMP://��Ȼ��IPV6�Ķ��壬���Ǻ�IPV4��һ����
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
        KdPrint(("\nARP�Ĺ㲥���ģ��Ͳ������ˡ�\n"));
        return;
    }

    if (arp->HardwareAddressLength != 6)
    {
        KdPrint(("\n����ARP���ĵ�MAC��ַ�ĳ��Ȳ�Ϊ6�ֽڡ�\n"));
    }

    if (arp->ProtocolAddressLength != 4)//IPV4_VERSION
    {
        KdPrint(("\n����ARP���ĵ�IP�ĳ��Ȳ�Ϊ4�ֽڡ�\n"));
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

                RtlIpv4AddressToString((const IN_ADDR *)&ami->SenderProtocolAddress, src_ipv4);//warning C4366: һԪ��&��������Ľ��������δ����ġ��ڴ����ָ��µġ�
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
                ע�⣺peh->Destination == EUI48_BROADCAST_INIT �ǹ㲥��
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
        KdPrint(("\n���֣�p_ipv6->VersionClassFlow != IPV6_VERSION�����ǵ��ڣ�0X%X��\n", p_ipv6->VersionClassFlow));
    }

    KdPrint(("IPV6:Destination MAC:%02X%02X%02X%02X%02X%02X,Source MAC:%02X%02X%02X%02X%02X%02X,Source IP:%s,Destination IP:%s\n",
        peh->Destination.Byte[0],peh->Destination.Byte[1],peh->Destination.Byte[2],peh->Destination.Byte[3],peh->Destination.Byte[4],peh->Destination.Byte[5],
        peh->Source.Byte[0],peh->Source.Byte[1],peh->Source.Byte[2],peh->Source.Byte[3],peh->Source.Byte[4],peh->Source.Byte[5],
        source_ipv6, 
        destination_ipv6));    

    /*
    ������д���һ�����������
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
    PETHERNET_HEADER peh = packet;//Ӧ������ṹ����ʶ�����̫������

    if(peh->Type == RtlUshortByteSwap(ETHERNET_TYPE_IPV4) ) 
    {	
        Analytical_ip_packet(packet, Length, Send_Receive);
    }
    else if(peh->Type == RtlUshortByteSwap(ETHERNET_TYPE_ARP)) //RARPҲ�����8035
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
        ժ�ԣ�TCPIP����һ�ĵڶ��£�
        ���˵��ǣ� 802�������Ч����ֵ����̫������Ч����ֵ��һ��ͬ���������Ϳ��Զ�����֡��ʽ�������֡�
        �����ԣ����﷢�ֵ�ֵ�У�0XCC88��0XA788
        */
        DbgPrint("\n����������ʽ�İ�Length : 0X%X�����ܾͲ�����̫�����ˡ�\n", peh->Type);
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

        NdisQueryMdl(CurrentMdl, &VirtualAddress, &Length, NormalPagePriority);//��ȡ�����ַ�ʹ�С��

        packet = VirtualAddress;

        if (CurrentMdlOffset != 0)
        {
            packet = (char *)packet + CurrentMdlOffset;
            Length -= CurrentMdlOffset;            
        }

        //safe_DbgPrint((PUCHAR)(packet), (ULONG)Length);//(ULONG)(Length)//�����IRQL���ߣ����˴�ӡ��Ϣ��һ��˼·�ǽ���IRQL���߹����̡߳�

        Analytical_packet(packet, Length, Send_Receive);
    }
}
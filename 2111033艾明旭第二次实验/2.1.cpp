//// 2.1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
////
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)
#include <Winsock2.h>
#include<iostream>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
using namespace std;

#pragma pack(1)//字节对齐方式

typedef struct IPheader_t {		//IP首部
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP	
	WORD TotalLen;//总长度
	WORD ID;//标识
	WORD Flag_Segment;//标志 片偏移
	WORD Checksum;//头部校验和	
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	BYTE Ver_HLen;//IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	BYTE TOS;//服务类型
	
}IPheader_t;

typedef struct FrameHeader_t {		//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct Data_t {		//数据包
	FrameHeader_t FrameHeader;
	IPheader_t IPheader;
}Data_t;



#pragma pack()//恢复缺省对齐方式

void PacketHandle(u_char*, const struct pcap_pkthdr*, const u_char*);
void IP_Packet_Handle(const struct pcap_pkthdr*, const u_char*);

void PacketHandle(u_char* argunment, const struct pcap_pkthdr* pkt_head, const u_char* pkt_data)
{
	FrameHeader_t* ethernet_protocol;		//以太网协议
	u_short ethernet_type;		//以太网类型
	u_char* mac_string;			//以太网地址
	//获取以太网数据内容
	ethernet_protocol = (FrameHeader_t*)pkt_data;
	ethernet_type = ntohs(ethernet_protocol->FrameType);
	printf("以太网类型为 :\t");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		printf("网络层IPv4协议\n");
		break;
	case 0x0806:
		printf("网络层ARP协议\n");
		break;
	case 0x8035:
		printf("网络层RARP协议\n");
		break;
	default:
		printf("网络层协议未知\n");
		break;
	}
	mac_string = ethernet_protocol->SrcMAC;
	printf("Mac源地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
	);
	mac_string = ethernet_protocol->DesMAC;
	printf("Mac目的地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
	);
	if (ethernet_type == 0x0800)
	{
		IP_Packet_Handle(pkt_head, pkt_data);
	}
}

void IP_Packet_Handle(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	IPheader_t* IPheader;
	IPheader = (IPheader_t*)(pkt_data + 14);//IP包的内容在原有物理帧后14字节开始
	sockaddr_in source, dest;
	char sourceIP[16], destIP[16];
	source.sin_addr.s_addr = IPheader->SrcIP;
	dest.sin_addr.s_addr = IPheader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), 16);
	strncpy(destIP, inet_ntoa(dest.sin_addr), 16);
	printf("版本：%d\n", IPheader->Ver_HLen >> 4);
	printf("IP协议首部长度：%d Bytes\n", (IPheader->Ver_HLen & 0x0f) * 4);
	printf("服务类型：%d\n", IPheader->TOS);
	printf("总长度：%d\n", ntohs(IPheader->TotalLen));
	printf("标识：0x%.4x (%i)\n", ntohs(IPheader->ID));
	printf("标志：%d\n", ntohs(IPheader->Flag_Segment));
	printf("片偏移：%d\n", (IPheader->Flag_Segment) & 0x8000 >> 15);
	printf("生存时间：%d\n", IPheader->TTL);
	printf("协议号：%d\n", IPheader->Protocol);
	printf("协议种类：");
	switch (IPheader->Protocol)
	{
	case 1:
		printf("ICMP\n");
		break;
	case 2:
		printf("IGMP\n");
		break;
	case 6:
		printf("TCP\n");
		break;
	case 17:
		printf("UDP\n");
		break;
	default:
		break;
	}
	printf("首部检验和：0x%.4x\n", ntohs(IPheader->Checksum));
	printf("源地址：%s\n", sourceIP);
	printf("目的地址：%s\n", destIP);
	cout << "--------------------------------------------------------------------------------" << endl;
}

int main()
{
	pcap_if_t* alldevs;//指向设备链表首部的指针
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int num = 0;//接口数量
	int n;
	int read_count;	//获得本机的设备列表
	int s = 0;
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		cout << "获取本机错误" << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		cout << dec << num << ":" << d->name << endl;//利用d->name获取该网络接口设备的名字
		if (d->description == NULL)//利用d->description获取该网络接口设备的描述信息
		{
			cout << "无信息" << endl;
		}
		else
		{			
			cout << d->description << endl;
		}
	}
	if (num == 0)
	{
		cout << "无可用接口" << endl;
		return 0;
	}	
	{
		cout << "请输入要打开的网络接口号" << "（1~" << num << "）：" << endl;
		cin >> n;
		num = 0;
		for (d = alldevs; num < (n - 1); num++)
		{
			d = d->next;
		}//跳转到选中的网络接口号
		pcap_t* adhandle;
		adhandle = pcap_open(d->name,		//设备名
			65536,		//要捕获的数据包的部分
			PCAP_OPENFLAG_PROMISCUOUS,		//混杂模式
			1000,			//超时时间
			NULL,		//远程机器验证
			errbuf		//错误缓冲池
		);
		if (adhandle == NULL)
		{
			cout << "错误，无法打开" << endl;
			pcap_freealldevs(alldevs);
			return 0;
		}
		else
		{
			cout << "监听：" << d->description << endl;
			pcap_freealldevs(alldevs);
		}
		if (s == 0)
		{
			cout << "要捕获的数据包的个数：" << endl;
			cin >> read_count;			
			if (read_count == 0)
			{				
				pcap_close(adhandle);
			}
			else
			{
				pcap_loop(adhandle, read_count, (pcap_handler)PacketHandle, NULL);				
				read_count = 0;
			}
		}		
	}	
	return 0;
}


//// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
//// 调试程序: F5 或调试 >“开始调试”菜单
//
//// 入门使用技巧: 
////   1. 使用解决方案资源管理器窗口添加/管理文件
////   2. 使用团队资源管理器窗口连接到源代码管理
////   3. 使用输出窗口查看生成输出和其他消息
////   4. 使用错误列表窗口查看错误
////   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
////   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

//
//#define HAVE_REMOTE
//
//#define WM_PACKET WM_USER + 1 //用户自定义消息
//
//#include <pcap.h>
//#include <time.h>
//#include <stdio.h>
//#include <iostream>
//
//#include<iostream>
//#include"pcap.h"
//#include<iomanip>
//#include<WS2tcpip.h>
//#include<windows.h>
//#include<cstdlib>
//#pragma comment(lib,"wpcap.lib")
//#pragma comment(lib,"packet.lib")
//#pragma comment(lib,"wsock32.lib")
//#pragma comment(lib,"ws2_32.lib")
//
//#pragma warning(disable : 4996)
//
//using namespace std;
//
//#pragma pack(1)
//typedef struct FrameHeader_t //帧首部
//{
//    BYTE DesMAC[6]; //目的地址
//    BYTE SrcMAC[6]; //源地址
//    WORD FrameType; //帧类型
//} FrameHeader_t;
//
//typedef struct IPHeader_t //IP首部
//{
//    BYTE Ver_HLen;
//    BYTE TOS;
//    WORD TotalLen;
//    WORD ID;
//    WORD Flag_Segment;
//    BYTE TTL;
//    BYTE Protocal;
//    WORD Checksum;
//    ULONG SrcIP;
//    ULONG DstIP;
//} IPHeader_t;
//
//typedef struct Data_t //包含帧首部和IP首部的数据包
//{
//    FrameHeader_t FrameHeader;
//    IPHeader_t IPHeader;
//} Data_t;
//
//#pragma pack()
//
//
//// 以下程序为根据以上代码所设计的捕获数据报的程序
//
//
///* 对packet handler函数进行声明 */
//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
//
//#pragma comment(lib,"wpcap.lib")
//
//int main(int argc, char* argv[])
//{
//    pcap_if_t* alldevs;
//    pcap_if_t* d;
//    int interface_num; // 先声明之后用户选择要用到的端口号
//    int i = 0;
//    pcap_t* adhandle;
//    char errbuf[PCAP_ERRBUF_SIZE];
//    char error1[9];
//    error1[0] = 'r';
//    error1[1] = 'p';
//    error1[2] = 'c';
//    error1[3] = 'a';
//    error1[4] = 'p';
//    error1[5] = ':';
//    error1[6] = '/';
//    error1[7] = '/';
//    error1[8] = '\0';
//    /* 获取本机设备列表 */
//    if (pcap_findalldevs_ex(error1, NULL, &alldevs, errbuf) == -1)
//    {
//        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
//        exit(1);
//    }
//    /* 打印列表 */
//    for (d = alldevs; d; d = d->next)
//    {
//        printf("%d. %s", ++i, d->name);
//        if (d->description)
//            printf(" (%s)\n", d->description);
//        else
//            printf(" (No description available)\n");
//    }
//    if (i == 0)
//    {
//        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
//        return -1;
//    }
//    printf("Enter the interface number which you like between (1 —— %d):", i); // 输入你想要监听的接口
//    scanf("%d", &interface_num);
//    if (interface_num < 1 || interface_num > i)
//    {
//        printf("\nInterface number out of range.\n");
//        /* 释放设备列表 */
//        pcap_freealldevs(alldevs);
//        return -1;
//    }
//    /* 跳转到选中的适配器 */
//    for (d = alldevs, i = 0; i < interface_num - 1; d = d->next, i++);
//    /* 打开设备 */
//    if ((adhandle = pcap_open(d->name,          // 设备名
//        65535,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
//        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
//        1000,             // 读取超时时间
//        NULL,             // 远程机器验证
//        errbuf            // 错误缓冲池
//    )) == NULL)
//    {
//        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
//        /* 释放设备列表 */
//        pcap_freealldevs(alldevs);
//        return -1;
//    }
//    printf("\nlistening on %s...\n", d->description);
//    /* 开始捕获 */
//    pcap_loop(adhandle, 0, packet_handler, NULL);
//    /* 释放设备列表，因为已经捕获到了数据包 */
//    pcap_freealldevs(alldevs);
//    getchar();
//    cout << "jieshu";
//    return 0;
//}
//
//
///* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
//void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
//{
//    struct tm* ltime;
//    char timestr[16];
//    time_t local_tv_sec;
//    /* 将时间戳转换成可识别的格式 */
//    local_tv_sec = header->ts.tv_sec;
//    ltime = localtime(&local_tv_sec);
//    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
//    printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);
//    // 检验校验和
//    Data_t* IPPacket;
//    WORD RecvChecksum;
//    IPPacket = (Data_t*)pkt_data;
//    RecvChecksum = IPPacket->IPHeader.Checksum;
//    // 需要编码的地方，仿照校验和，写输出语句，输出源MAC地址、目的MAC地址和类型/长度字段的值的语句    
//    printf("------------------------------------------------------\n");
//    printf("数据报的源MAC地址为：%02x:", IPPacket->FrameHeader.SrcMAC[0]);
//    printf("%02x:", IPPacket->FrameHeader.SrcMAC[1]);
//    printf("%02x:", IPPacket->FrameHeader.SrcMAC[2]);
//    printf("%02x:", IPPacket->FrameHeader.SrcMAC[3]);
//    printf("%02x:", IPPacket->FrameHeader.SrcMAC[4]);
//    printf("%02x\n", IPPacket->FrameHeader.SrcMAC[5]);
//    printf("数据报的目的MAC地址为：%02x:", IPPacket->FrameHeader.DesMAC[0]);
//    printf("%02x:", IPPacket->FrameHeader.DesMAC[1]);
//    printf("%02x:", IPPacket->FrameHeader.DesMAC[2]);
//    printf("%02x:", IPPacket->FrameHeader.DesMAC[3]);
//    printf("%02x:", IPPacket->FrameHeader.DesMAC[4]);
//    printf("%02x\n", IPPacket->FrameHeader.DesMAC[5]);
//    u_short ethernet_type;
//    ethernet_type = ntohs(IPPacket->FrameHeader.FrameType);
//    printf("其类型/长度字段的值为：%04x\n", ethernet_type);
//    cout << "其类型为：";
//    switch (ethernet_type)
//    {
//    case 0x0800:
//        cout << "IP";
//        break;
//    case 0x0806:
//        cout << "ARP";
//        break;
//    case 0x0835:
//        cout << "RARP";
//        break;
//    default:
//        cout << "Unknown Protocol";
//        break;
//    }
//    printf("\n");
//    printf("------------------------------------------------------\n");
//}
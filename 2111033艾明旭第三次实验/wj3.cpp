// wj3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Winsock2.h>
#include<iostream>
#include <pcap.h>
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")

#pragma warning(disable : 4996)

using namespace std;

#pragma pack(1)//字节对齐方式

typedef struct FrameHeader_t {		//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct ARPFrame_t {//IP首部
	FrameHeader_t FrameHeader;
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;//操作类型
	BYTE SendHa[6];//发送方MAC地址
	DWORD SendIP;//发送方IP地址
	BYTE RecvHa[6];//接收方MAC地址
	DWORD RecvIP;//接收方IP地址
}ARPFrame_t;
# pragma pack()

// ARP初始帧的声明
ARPFrame_t ARPFrame;

int main()
{
	pcap_if_t* alldevs;//指向设备链表首部的指针
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int num = 0;//接口数量
	int n;
	char ip[20] = {};
	char ip1[20] = {};
	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		cout << "获取本机设备错误" << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		cout << dec << num << ":" << d->name << endl;//利用d->name获取该网络接口设备的名字
		if (d->description != NULL)//利用d->description获取该网络接口设备的描述信息
		{
			cout << d->description << endl;
		}
		else
		{
			cout << "无描述信息" << endl;
		}
		//获取该网络接口设备的ip地址信息
		pcap_addr_t* a; // 网络适配器的地址
		for (a = d->addresses; a != NULL; a = a->next)
		{
			switch (a->addr->sa_family)//sa_family代表了地址的类型
			{
			case AF_INET://IPV4
				printf("Address Family Name:AF_INET\t");
				if (a->addr != NULL)
				{
					//strcpy(ip, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "IP_Address:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				}
				break;
			case AF_INET6://IPV6
				cout << "Address Family Name:AF_INET6" << endl;
				break;
			default:
				break;
			}
		}
		//cout << "----------------------------------------------------------------------------------------------------------" << endl;
	}
	if (num == 0)
	{
		cout << "无可用接口" << endl;
		return 0;
	}
	cout << "请输入要打开的网络接口号" << "（1~" << num << "）：" << endl;
	num = 0;
	cin >> n;
	// 跳转到选中的网络接口号
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}
	strcpy(ip, inet_ntoa(((struct sockaddr_in*)(d->addresses)->addr)->sin_addr));
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
		cout << "产生错误，无法打开设备" << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		cout << "监听：" << d->description << endl;
		pcap_freealldevs(alldevs);
	}
	//设置ARP帧的内容
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);// 帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	//将ARPFrame.SendHa设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x66;
	}
	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr("112.112.112.112");
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;//表示目的地址未知
	}
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = inet_addr(ip);
	//用网卡发送ARPFrame中的内容，报文长度为sizeof(ARPFrame_t)，如果发送成功，返回0
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		//cout << "发送失败，退出程序" << endl;
		//return -1;
	}
	// 声明即将捕获的ARP帧
	ARPFrame_t* IPPacket;
	// 开始进行捕获
	ARPFrame.SendIP = inet_addr(ip);
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x66;
	}
	while (1)//可能会有多条消息
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//如果帧类型为ARP并且操作为ARP应答
			{
				printf("Mac地址：\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket->FrameHeader.SrcMAC[0],
					IPPacket->FrameHeader.SrcMAC[1],
					IPPacket->FrameHeader.SrcMAC[2],
					IPPacket->FrameHeader.SrcMAC[3],
					IPPacket->FrameHeader.SrcMAC[4],
					IPPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = IPPacket->SendHa[i];
		ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}
	cout << "请输入IP：" << endl;
	cin >> ip1;
	ARPFrame.RecvIP = inet_addr(ip1);
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		//cout << "发送失败，退出程序" << endl;
		//return -1;
	}
	else
	{
		cout << "发送成功" << endl;
	}
	ARPFrame_t* IPPacket1;
	while (1)//可能会有多条消息
	{
		pcap_pkthdr* pkt_header1;
		const u_char* pkt_data1;
		int rtnNew = pcap_next_ex(adhandle, &pkt_header1, &pkt_data1);
		if (rtnNew == 1)
		{
			IPPacket1 = (ARPFrame_t*)pkt_data1;
			//cout << ntohs(IPPacket1->SendIP) << " " << inet_addr(ip1) << " " << IPPacket1->SendIP;
			if ((ntohs(IPPacket1->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket1->Operation) == 0x0002) && (IPPacket1->SendIP == inet_addr(ip1)))//如果帧类型为ARP并且操作为ARP应答
			{
				printf("Mac地址：\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket1->FrameHeader.SrcMAC[0],
					IPPacket1->FrameHeader.SrcMAC[1],
					IPPacket1->FrameHeader.SrcMAC[2],
					IPPacket1->FrameHeader.SrcMAC[3],
					IPPacket1->FrameHeader.SrcMAC[4],
					IPPacket1->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}
	
	pcap_close(adhandle);
	return 0;
}
// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

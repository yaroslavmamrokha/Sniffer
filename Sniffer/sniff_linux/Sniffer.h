#ifndef SNIFFER_H
#define SNIFFER_H

#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#ifdef _WIN32
#include<winsock2.h>
#include <conio.h>
#include<windows.h>
#pragma comment(lib, "ws2_32.lib")
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#else
#include<sys/socket.h>
#include<arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include<unistd.h>
#include <netdb.h>
#endif
#define MAX_SIZE 65536
#define WSAVERS 2
#define NO_FILTERS 0


#define BUF_SIZE 255
struct Ip{
	unsigned char version:4, header_len:4;
	unsigned char serv_type;
	short total_len;
	unsigned short packet_id;
	short offset;
	unsigned char packet_time;
	unsigned char protocol;
	unsigned short control_sum;
	unsigned long src, dst;


};

class Sniff_sock{
private:
	int raw;
	char buffer[MAX_SIZE];
	struct sockaddr_in source, dest,srv;
	struct in_addr addr;
	int choice;
	int ICMP, IGMP, TCP, UDP, other;
	struct hostent *local;
	char hostname[BUF_SIZE];
	int def_size;
#ifdef _WIN32
	WSADATA wsa;
#endif
	FILE* log;
	int recv_size;
	struct sockaddr recv;
public:
Sniff_sock();
~Sniff_sock();
void Host_Choose();
void Recv_Packet();//get all packets without filtering
void Show_Packet(int);//no data , log into the file
void Init_Socket();
void Write_To_File(struct Ip*);
void Start(int);
};
#endif

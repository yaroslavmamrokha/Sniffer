#include"Sniffer.h"
Sniff_sock::Sniff_sock(){
	raw = 0;
	def_size = sizeof(source);
	recv_size = 0;
	log = fopen("log.txt", "a+");
	fprintf(log, "---------------Packet logging---------------\n");
	fclose(log);
	ICMP = 0;
	IGMP = 0;
	TCP = 0;
	UDP = 0;
	other = 0;
	memset(&source, 0 ,def_size);
	memset(&dest, 0 ,def_size);
	memset(&recv,0, sizeof(recv));
	memset(buffer, 0, MAX_SIZE);

}

Sniff_sock::~Sniff_sock(){
#ifdef _WIN32
	WSACleanup();
	closesocket(raw);
#else
	close(raw);
#endif
}
void Sniff_sock::Host_Choose(){
	int i = 0;
if (gethostname(hostname, sizeof(hostname))<0)
	{
		printf("Error ");
		exit(1);
	}
	printf("\nHost name : %s \n",hostname);

	//Retrive IP address of the local host
	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error ");
		exit(1);
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n",i,inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d",&choice);
	if(choice>i || choice< 0)
	{
		printf("Bad input!!\n");
		system("CLS");
		Host_Choose();
	}
}
//@brief:  Socket initzialisation, and putting socket in promiscuous mode also allow user to choose host

void Sniff_sock::Init_Socket(){
    int promiscuous =1;
	int Temp, i = 0;
#ifdef _WIN32
	if(WSAStartup(MAKEWORD(WSAVERS,WSAVERS),&wsa)<0)
	{
		printf("Error!! coudn't initialise WSA version\n");
		exit(1);
	}
#endif
	raw=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	if(raw<0){
		printf("Failed to init socket!!\n");
		exit(1);
	}


	Host_Choose();
	memset(&srv, 0, sizeof(srv));
	memcpy(&srv.sin_addr.s_addr,local->h_addr_list[choice],sizeof(srv.sin_addr.s_addr));
	srv.sin_family = AF_INET;
		srv.sin_port = htons(120);

		if(bind(raw, (struct sockaddr*)&srv, sizeof(srv))<0){
			printf("Failed to bind!\n");
			exit(1);
		}
		Temp = 1;
#ifdef _WIN32
		if (promiscuous){	/* -d on the command line to disable promiscuous mode */
		if (WSAIoctl(raw,SIO_RCVALL,&Temp,sizeof(Temp),NULL,NULL,(LPDWORD)&choice,NULL,NULL) == SOCKET_ERROR){
			printf("failed to set promiscuous mode\n");
		exit(1);
		}
	}
#else
		struct ifreq eth;
		strcpy(eth.ifr_name, "Eth");
		ioctl(raw, SIOCGIFFLAGS, &eth);
		eth.ifr_flags |= IFF_PROMISC;
		ioctl(raw, SIOCSIFFLAGS, &eth);
#endif

}
//@brief: Function Recive packets
void Sniff_sock::Recv_Packet(){
#ifdef _WIN32
	int s_size = sizeof(recv);
	#else
	socklen_t s_size = sizeof(recv);
	#endif
	while(1){
	recv_size = recvfrom(raw, buffer, MAX_SIZE, NULL, &recv, &s_size);
	if(recv_size<0){
		printf("Failed to recive packet!\n");
		exit(1);
	}
	break;
	}
}
//@brief: Function write packet info into file
//@[in]: option choosen filter
void Sniff_sock::Show_Packet(int option){
	struct Ip* ip_head = (struct Ip*)buffer;
	source.sin_addr.s_addr = ip_head->src;
	dest.sin_addr.s_addr = ip_head->dst;

	switch((unsigned int)ip_head->protocol){
	case 1:
		ICMP++;
		break;
	case 2:
		IGMP++;
		break;
	case 6:
		TCP++;
		break;
	case 17:
		UDP++;
		break;
	default:
		other++;
		break;
	}

	system("CLS");
	printf("ICMP packets: %d   IGMP packets: %d   TCP packets: %d   UDP packets: %d    Other packets: %d\n",ICMP,IGMP,TCP,UDP, other);
	if(option == NO_FILTERS){
		Write_To_File(ip_head);
	}else{	if((unsigned int)ip_head->protocol == option){
		Write_To_File(ip_head);
	}
	}
}
//@brief: Function Starts Packet sniffing
//@[in]: option - choosen filter
void Sniff_sock::Start(int option){
	int n = 0;
	Init_Socket();
	while(n != 5000){
		Recv_Packet();
		Show_Packet(option);
		n++;
	}


}
//@brief: Function log packet into file
//@[in]: ip_head struct that contain information about packet
void Sniff_sock::Write_To_File(struct Ip* ip_head){
	log = fopen("log.txt", "a+");
	if(log == NULL){
		printf("Failed to open file\n");
		exit(1);
	}

	fprintf(log, "---------------------------------PACKET INFO------------------------------------------\n");
	fprintf(log, "Packet Version: %d\n",(unsigned int)ip_head->version);
	fprintf(log, "Header Length: %d\n",((unsigned int)ip_head->header_len*4));
	fprintf(log, "Service Type: %d\n",(unsigned int)ip_head->serv_type);
	fprintf(log, "Total Length: %d\n",ntohs(ip_head->total_len));
	fprintf(log, "Packet ID: %d\n",ntohs(ip_head->packet_id));
	fprintf(log, "Packet time to live: %d\n",(unsigned int)ip_head->packet_time);
	fprintf(log, "Protocol: %d\n",(unsigned int)ip_head->protocol);
	fprintf(log, "Control sum: %d\n",ntohs(ip_head->control_sum));
	fprintf(log, "Source IP address: %s\n",inet_ntoa(source.sin_addr));
	fprintf(log, "Destination IP address: %s\n",inet_ntoa(dest.sin_addr));
	fprintf(log, "--------------------------------------------------------------------------------------\n");
	fclose(log);
}

#include"Sniffer.h"
Sniff_sock* sniffer = new Sniff_sock;
char ch;
char a[15];

int option;
//@brief: function display menu. Used recursive method if bad input.
void Menu(){
	printf("-------------------Info-------------------\n");
	printf("To Start Sniffing press <1>\n");
	printf("To Exit press <2>\n");
	printf("Packet logs in File <log.txt>\n");
#ifdef _WIN32
	ch = getch();
#else
	scanf("%s", a);
	ch = a[0];
#endif
	switch(ch){
	case '1':
		printf("Choose filter Option!: \n");
		printf("ICMP: = 1\n");
		printf("IGMP: = 2\n");
		printf("TCP: = 6\n");
		printf("UDP: = 17\n");
		printf("EGP: = 8\n");
		printf("IGP: = 9\n");
		printf("IRTP: = 28\n");
		printf("HMP: = 20\n");
		printf("DDP: = 37\n");
		printf("TP++: = 39\n");
		printf("XTP: = 36\n");
		printf("3PC: = 34\n");
		printf("Without Filters: = 0\n");
		printf("Your choice: = ");
		scanf("%d", &option);
		sniffer->Start(option);
		printf("Finished Sniffing. Check log.txt for information about recieved packets!\n");
		break;
	case '2':
		break;
	default:
		printf("Bad input!\n");
		#ifdef _WIN32
		Sleep(1000);
        system("CLS");
        #else
        sleep(1);
        system("clear");
        #endif
		Menu();

	}
}
int main(){
	remove("log.txt");
	Menu();
	printf("Exiting sniffer application....\n");
	delete sniffer;
	return 0;
}

#include <pcap.h>
#include <conio.h>
#include <hell.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#define LINE_LEN 16

using namespace std;
int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	int res;


	/* Open the capture file */
	if ((fp = pcap_open_offline("C:\\Users\\galat\\Documents\\GitHub\\Artem\\sv.pcap",			// name of the device
						 errbuf					// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
		return -1;
	}
	/* Retrieve the packets from the file */
	res = pcap_next_ex(fp, &header, &pkt_data);
	
	/* print pkt timestamp and pkt len */
	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
	
	/* Print the packet */
	for (i=1; (i < header->caplen + 1 ) ; i++)
	{
		printf("%.2x ", pkt_data[i-1]);
		if ( (i % LINE_LEN) == 0) printf("\n");
	}
	
	printf("\n\n");		
	
	SV_PROT prot;
	WildFox(pkt_data,header,&prot);
	fprintf(stderr,"che-to sdelalos \n");
	std::cout<<"Dest (";
	for(int i=0;i<6;i++){
		printf("%.2x:",int(prot.Destinatinion[i]));
	}
	std::cout<<string (1,'\b')<<")\n";
	std::cout<<"Source (";
	for(int i=0;i<6;i++){
		printf("%.2x:",int(prot.Source[i]));
	}
	std::cout<<string (1,'\b')<<")\n";
	std::cout<<"Type (";
	printf("%.2x",int(prot.Type));
	std::cout<<")\n";
	std::cout<<"AppID (";
	printf("%.2x",int(prot.AppID));
	std::cout<<")\n";
	std::cout<<"Lenght (";
	printf("%.d",int(prot.Lenght));
	std::cout<<")\n";
	std::cout<<"Res1 (";
	printf("%.2x",int(prot.Res1));
	std::cout<<")\n";
	std::cout<<"Res2 (";
	printf("%.2x",int(prot.Res2));
	std::cout<<")\n";
	std::cout<<"noAsdu (";
	printf("%d",int(prot.noAsdu));
	std::cout<<")\n";
	std::cout<<"svID (";
	for(int i=0;i<10;i++){
		printf("%.c",int(prot.svID[i]));
	}
	std::cout<<")\n";
	std::cout<<"smpCnt (";
	printf("%d",int(prot.smpCnt));
	std::cout<<")\n";
	std::cout<<"confRef (";
	printf("%d",int(prot.confRef));
	std::cout<<")\n";
	std::cout<<"smpSynch (";
	printf("%d",int(prot.smpSynch));
	std::cout<<")\n";
	std::cout<<"Data (\n";
	for(int i=1;i<65;i++){
		printf("%.2x ",int(prot.Data[i-1]));
		if ( (i % LINE_LEN) == 0 ) printf("\n");
	}
	std::cout<<")\n";






    getch();
	pcap_close(fp);
	return 0;
}


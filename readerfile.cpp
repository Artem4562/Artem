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
	if ((fp = pcap_open_offline("C:\\Users\\User\\Documents\\GitHub\\Artem\\sv.pcap",			// name of the device
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
	cout<<"Dest (";
	for(int i=0;i<6;i++){
		printf("%.2x:",int(prot.Destination[i]));
	}
	cout<<string (1,'\b')<<")\n";
	cout<<"Source (";
	for(int i=0;i<6;i++){
		printf("%.2x:",int(prot.Source[i]));
	}
	cout<<string (1,'\b')<<")\n";
	cout<<"Type (";
	printf("%.2x",int(prot.Type));
	cout<<")\n";
	cout<<"AppID (";
	printf("%.2x",int(prot.AppID));
	cout<<")\n";
	cout<<"Lenght (";
	printf("%.d",int(prot.Lenght));
	cout<<")\n";
	cout<<"Res1 (";
	printf("%.2x",int(prot.Res1));
	cout<<")\n";
	cout<<"Res2 (";
	printf("%.2x",int(prot.Res2));
	cout<<")\n";
	cout<<"noAsdu (";
	printf("%d",int(prot.noAsdu));
	cout<<")\n";
	cout<<"svID (";
	for(int i=0;i<10;i++){
		printf("%.c",int(prot.svID[i]));
	}
	cout<<")\n";
	cout<<"smpCnt (";
	printf("%d",int(prot.smpCnt));
	cout<<")\n";
	cout<<"confRef (";
	printf("%d",int(prot.confRef));
	cout<<")\n";
	cout<<"smpSynch (";
	printf("%d",int(prot.smpSynch));
	cout<<")\n";
	cout<<"Data (\n";
	for(int i=1;i<65;i++){
		printf("%.2x ",int(prot.Data[i-1]));
		if ( (i % LINE_LEN) == 0 ) printf("\n");
	}
	cout<<")\n";






    getch();
	pcap_close(fp);
	return 0;
}


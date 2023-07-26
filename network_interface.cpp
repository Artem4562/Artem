#include <pcap.h>  
#include <iostream>
#include <string>
#include <fstream>
#include <stdio.h>
#include <conio.h>

using namespace std;


#define MAX_PRINT 80
#define MAX_LINE 16



void usage();




int main(int argc, char **argv){
	string path ="../name.txt";
	ifstream fin;
	fin.open(path);
	if (!fin.is_open()){
		cout<< "FATAL ERROR"<< endl;
	}
	else {
		cout<< "file is open!"<<endl;
		string str="";
		while(!fin.eof()){
			getline(fin, str);
			cout<<str<<endl;
		}
	}
	fin.close();
    getch();


	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	char *source = NULL;
	char *ofilename = NULL;
	char *filter = NULL;
	int i;
	pcap_dumper_t *dumpfile;
	struct bpf_program fcode;
	bpf_u_int32 NetMask;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	


	if (argc == 1)
	{
		usage();
		return -1;
	}

	/* Parse parameters */
	for(i=1;i < argc; i+= 2)
	{
		switch (argv[i] [1])
		{
			case 's':
			{
				source=argv[i+1];
			};
			break;
			
			case 'o':
			{
				ofilename=argv[i+1];
			};
			break;

			case 'f':
			{
				filter=argv[i+1];
			};
			break;
		}
	}
	
	// open a capture from the network
	if (source != NULL)
	{
		fp = pcap_create(source, errbuf);
		if (fp == NULL) {
			fprintf(stderr, "pcap_create error: %s\n", errbuf);
			return -2;
		}
		res = pcap_set_snaplen(fp, 65536);
		if (res < 0) {
			fprintf(stderr, "pcap_set_snaplen error: %s\n", pcap_statustostr(res));
			return -2;
		}
		res = pcap_set_promisc(fp, 1);
		if (res < 0) {
			fprintf(stderr, "pcap_set_promisc error: %s\n", pcap_statustostr(res));
			return -2;
		}
		res = pcap_set_timeout(fp, 1000);
		if (res < 0) {
			fprintf(stderr, "pcap_set_timeout error: %s\n", pcap_statustostr(res));
			return -2;
		}
		res = pcap_activate(fp);
		if (res < 0) {
			fprintf(stderr, "pcap_activate error: %s\n", pcap_statustostr(res));
			return -2;
		}
	}
	else usage();

	if (filter != NULL)
	{
		// We should loop through the adapters returned by the pcap_findalldevs_ex()
		// in order to locate the correct one.
		//
		// Let's do things simpler: we suppose to be in a C class network ;-)
		NetMask=0xffffff;

		//compile the filter
		if((res = pcap_compile(fp, &fcode, filter, 1, NetMask)) < 0)
		{
			fprintf(stderr,"\nError compiling filter: %s\n", pcap_statustostr(res));

			pcap_close(fp);
			return -3;
		}

		//set the filter
		if((res = pcap_setfilter(fp, &fcode))<0)
		{
			fprintf(stderr,"\nError setting the filter: %s\n", pcap_statustostr(res));

			pcap_close(fp);
			return -4;
		}

	}

	//open the dump file
	if (ofilename != NULL)
	{
		dumpfile= pcap_dump_open(fp, ofilename);

		if (dumpfile == NULL)
		{
			fprintf(stderr,"\nError opening output file: %s\n", pcap_geterr(fp));

			pcap_close(fp);
			return -5;
		}
	}
	else usage();

	//start the capture
 	while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{

		if(res == 0)
		/* Timeout elapsed */
		continue;

		//save the packet on the dump file
		pcap_dump((unsigned char *) dumpfile, header, pkt_data);

	}

	pcap_close(fp);
	pcap_dump_close(dumpfile);

	return 0;
}


void usage()
{

	printf("\npf - Generic Packet Filter.\n");
	printf("\nUsage:\npf -s source -o output_file_name [-f filter_string]\n\n");
	exit(0);
}

#include <pcap.h>
#include <iostream>
#include <string.h>
#include <fstream>
#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <cstring>



using namespace std;


#define MAX_PRINT 80
#define MAX_LINE 16


void usage();


int main(int argc, char **argv){
	string path ="../name.txt";
	ifstream fin;
	usage();
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
	fprintf(stderr,"\nUsage:\npf -s %s -o %s [-f %s]\n\n",source,ofilename,filter);
	
	// open a capture from the network
	if (source != NULL)
	{
		if ( (fp= pcap_open(source,
                            100 /*snaplen*/,
                            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                            20 /*read timeout*/,
                            NULL /* remote authentication */,
                            errbuf)
                            ) == NULL)
        {
            fprintf(stderr,"\nError opening adapter: %s\n",errbuf);
            return -1;
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
			fprintf(stderr,"\nError compiling filter: %s\n", (res));

			pcap_close(fp);
			return -3;
		}

		//set the filter
		if((res = pcap_setfilter(fp, &fcode))<0)
		{
			fprintf(stderr,"\nError setting the filter: %s\n", (res));

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
	printf("\nUsage:\npf -s sourse -o output_file_name [-f filter_string]\n\n");
	exit(0);
}

#include <pcap.h>
#include <conio.h>
#include <hell.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <vector>
#include <algorithm>
#define LINE_LEN 16

using namespace std;



int main(int argc, char **argv)
{	
	vector<SV_PROT_NF_I> DataKrat;
	vector<SV_PROT_F_I> DataPoln;
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	struct bpf_program fcode;     //переменная для записи фильтра
	int res;  //переменная под ошибки 
	bpf_u_int32 mask;   /* Сетевая маска устройства */
	bpf_u_int32 net;	/* IP устройства */


	/* Open the capture file */
	if ((fp = pcap_open_offline("../SVLong.pcapng",			// name of the device
						 errbuf							// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
		return -1;
	}


		if((res = pcap_compile(fp, &fcode, "not udp", 1, 0)) < 0) //составление фльтра 
			{	
				cout<<"\nError compiling filter: "<< res <<'\n';
				getch();
				pcap_close(fp);
				return -3;
			}

			//set the filter
		if((res = pcap_setfilter(fp, &fcode))<0)   //применение фильтра 
			{
				cout<<"\nError setting the filter: "<< res <<'\n';
				getch();
				pcap_close(fp);
				return -4;
			}

	int k = 0;
	
	int id =0;
	bool flg;
	SV_PROT prot;
	while(k < 540000){
		k++;
		/* Retrieve the packets from the file */
		res = pcap_next_ex(fp, &header, &pkt_data);
		flg = false;
		int j = 0;
		WildFox(pkt_data,header,&prot);
		while(!flg && j<id){
			if(prot.AppID==DataKrat[j].AppID ) flg=true;
			j++;
		}
		j=0;
		if(!DataKrat.size() || !flg){
			SV_PROT_NF_I data;
			data.AppID = prot.AppID;
			data.Destination.insert(data.Destination.end(), &prot.Destination[0], &prot.Destination[LEN_ETHERNET_ADDR]);
			data.Source.insert(data.Source.end(), &prot.Source[0], &prot.Source[LEN_ETHERNET_ADDR]);
			data.svID.insert(data.svID.end(), &prot.svID[0], &prot.svID[prot.svID.size()]);
			data.id = id++;
			DataKrat.push_back(data);
		}
		while(j<id){
			if (DataKrat[j].opened){
				
			}
			j++;
		}


		//cout<<prot.Ia<<"\n";
	}
	cout<<k;
	pcap_close(fp);
	return 0;
}


#include <pcap.h>
#include <conio.h>
#include <hell.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <vector>
#include <algorithm>
#include <string>
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
	string name;
	name = string("../") + argv[1];
	if ((fp = pcap_open_offline(name.c_str(),			// name of the device
						 errbuf							// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file: %s.\n", errbuf);
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
	vector<char> t = {'N','G','r','i','d','_','c','a','b','l','e','_','1'};
	vector<SV_PROT_NF_I> DK = {
		SV_PROT_NF_I{{1,12,205,4,0,1},{12,239,175,48,222,46},16385,t,0},
		SV_PROT_NF_I{{2,12,205,4,0,1},{12,239,175,48,222,46},51638,t,1},
		SV_PROT_NF_I{{3,12,205,4,0,1},{12,239,175,48,222,46},13685,t,2},
		SV_PROT_NF_I{{4,12,205,4,0,1},{12,239,175,48,222,46},16385,t,3},
		SV_PROT_NF_I{{5,12,205,4,0,1},{12,239,175,48,222,46},16835,t,4},
		SV_PROT_NF_I{{6,12,205,4,0,1},{12,239,175,48,222,46},13685,t,5},
		SV_PROT_NF_I{{7,12,205,4,0,1},{12,239,175,48,222,46},16358,t,6},
		SV_PROT_NF_I{{8,12,205,4,0,1},{12,239,175,48,222,46},21635,t,7},
		SV_PROT_NF_I{{9,12,205,4,0,1},{12,239,175,48,222,46},16835,t,8},
		SV_PROT_NF_I{{10,12,205,4,0,1},{12,239,175,48,222,46},16385,t,9},
		SV_PROT_NF_I{{11,12,205,4,0,1},{12,239,175,48,222,46},16385,t,10},
		SV_PROT_NF_I{{12,12,205,4,0,1},{12,239,175,48,222,46},16385,t,11},
		SV_PROT_NF_I{{13,12,205,4,0,1},{12,239,175,48,222,46},16385,t,12},
		SV_PROT_NF_I{{14,12,205,4,0,1},{12,239,175,48,222,46},16385,t,13},
		SV_PROT_NF_I{{15,12,205,4,0,1},{12,239,175,48,222,46},16385,t,14}
	};


	int k = 0;
	SV_PROT prot;
	SV_PROT_NF_I data;
	int id =0;
	bool flg;
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
		if(!DataKrat.size() || !flg){
			data.AppID = prot.AppID;
			copy_n(prot.Destination, sizeof(prot.Destination), data.Destination);
			copy_n(prot.Source, sizeof(prot.Source), data.Source);
			data.svID = prot.svID;
			data.id = id++;
			DataKrat.push_back(data);
		}

	}
	cout<<k;
	pcap_close(fp);
	return 0;
}


#include <pcap.h>
#include <hell.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <string>
#include <DFT.hpp>
#define LINE_LEN 16

using namespace std;

void (*dispatcher) (u_char *, const struct pcap_pkthdr *, const u_char *);
void dispatcher_handler1(u_char *, const struct pcap_pkthdr *, const u_char *);
void dispatcher_handler2(u_char *, const struct pcap_pkthdr *, const u_char *);


static vector<SV_PROT_NF_I> DataKrat;
static SV_PROT_AMP datat;
static bool flg = false;
static bool fg = false;
static bool flag = false;
static int id =0;
static int kek=0;
static int MINUA=0;
static std::vector<SV_PROT_D> Result;

int main(int argc, char **argv)
{	
	kek = 10000*(int(argv[2][0])-48)+1000*int((argv[2][1])-48)+100*int((argv[2][2])-48)+10*int((argv[2][3])-48)+int((argv[2][4])-48);
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
	string name ;
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
				pcap_close(fp);
				return -3;
			}

			//set the filter
		if((res = pcap_setfilter(fp, &fcode))<0)   //применение фильтра 
			{
				cout<<"\nError setting the filter: "<< res <<'\n';
				pcap_close(fp);
				return -4;
			}




	if(!argv[2]) dispatcher = dispatcher_handler1; 
	else dispatcher = dispatcher_handler2;
	pcap_loop(fp,0,dispatcher,NULL);
	
	pcap_close(fp);
	return 0;
}

void dispatcher_handler1(u_char *temp1, 
						const struct pcap_pkthdr *header, 
						const u_char *pkt_data)
{
	
	SV_PROT prot;
	SV_PROT_NF_I data;
	bool flg = false;
	int j = 0;
	WildFox(pkt_data,header, &prot);
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

void dispatcher_handler2(u_char *temp1, 
						const struct pcap_pkthdr *header, 
						const u_char *pkt_data)
{	
	SV_PROT prot;
	WildFox(pkt_data,header, &prot);
	if(prot.AppID == kek ){
		if(MINUA==0 && MINUA>prot.Ua && !fg){
			MINUA=prot.Ua;
		}
		if(MINUA>prot.Ua && !fg){
			MINUA=prot.Ua;
			flag= true;
		}
		if(MINUA<prot.Ua && flag== true && !fg){
			fg= true;
		}

		if(!flg && fg && 0.001>(abs(float(prot.Ua)/MINUA))){
			flg = true;
		}

		if(flg){
			datat.push_back_prot(prot);
		}
		if(datat.Ia.size()==800){
			DFT_4000D_1S(800,datat,LOWPERF,&Result);
			datat.erase_prot_all();
		
			
		}
	}
}


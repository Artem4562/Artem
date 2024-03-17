#define _GNU_SOURCE
#include <pcap.h>
#include <hell.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <string>
#include <DFT.hpp>
#include <time.h>
#include <unistd.h>
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

	//accept signal from VSCode for pausing/stopping
    char *sudo_uid = getenv("SUDO_UID");
    if (sudo_uid)
        setresuid(0, 0, atoi(sudo_uid));

    printf("uid = %d\n", getuid());



	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	struct bpf_program fcode;     //переменная для записи фильтра
	int res;  //переменная под ошибки 
	bpf_u_int32 mask;   /* Сетевая маска устройства */
	bpf_u_int32 net;	/* IP устройства */
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	int inum;

	std::cin>>(kek);
	    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(dev=alldevs; dev; dev=dev->next)
    {
        printf("%d. %s", ++i, dev->name);
        if (dev->description)
            printf(" (%s)\n", dev->description);
        else
            printf(" (No description available)\n");
    }
    
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    std::cin>>(inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* Jump to the selected adapter */
    for(dev=alldevs, i=0; i< inum-1 ;dev=dev->next, i++);
    
    /* Open the device */
    if ( (fp= pcap_open_live(dev->name,         // name of the device
                              65536,            // portion of the packet to capture. 
                              true,             // 65536 guarantees that the whole packet will be captured on all the link layers
                              1000,             // read timeout            
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
		std::cout<<'\n'<<errbuf;
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

	if (pcap_datalink(fp) != DLT_EN10MB) 
		{
			fprintf(stderr, "Device %s doesn't provide Ethernet headers -not  supported\n", dev->name);
			return(2);
		}

	if((res = pcap_compile(fp, &fcode, "not udp and not ip and ether[12]=136 and ether[13]=186", 1, 0)) < 0) //составление фльтра 
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

    
    printf("\nlistening on %s...\n", dev->name);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    
	if(!kek) dispatcher = dispatcher_handler1; 
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
		if(datat.size()==800){
			DFT_4000D_1S(800,datat,LOWPERF,&Result);
			datat.erase_prot_all();
		
			
		}
	}
}


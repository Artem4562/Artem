#include <pcap.h>
#include <hell.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <string>
#include <DFT.hpp>
#include <time.h>
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
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	int inum;

	
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
    if ( (fp= pcap_open_live(dev->name,          // name of the device
                              65536,            // portion of the packet to capture. 
                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nlistening on %s...\n", dev->description);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* Retrieve the packets */
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0){
        
        if(res == 0)
            /* Timeout elapsed */
            continue;
        
        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        localtime_r(&local_tv_sec,&ltime);
        strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
        
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }
    
    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }
    
    return 0;
	
	
		/* Open the capture file */
	string name ;
	name = argv[1];
	if ((	fp = pcap_open_live(dev->name,     // name of the device
			BUFSIZ,
			0,
			10000,
			errbuf							// error buffer
			)) == NULL);
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




	if(!argv[2]<10) dispatcher = dispatcher_handler1; 
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


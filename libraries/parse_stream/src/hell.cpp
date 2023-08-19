#include <iostream>
#include <pcap.h>

typedef struct SV_Protocol 
{
    short Destinatinion[7];
    short Source[7];
    short *Type;
    short *AppID;
    unsigned short Lenght;
    short *Res1;
    short *Res2;
    int savapdu;
    int seqasdu;
    //int asdu;
    char *svID;
    short smpCnt;
    unsigned long confRef;
    short smpSynch;
    unsigned char Data[65];
} SV_PROT;

void WildFox(char *pkt_data, pcap_pkthdr *header, SV_PROT *package){
    int i;
    for(i = 0; i<14;i++){
        if(i<=5){
            package->Destinatinion[i]=pkt_data[i];
        }
        else if(6<=i<=11){
            package->Source[i-6]=pkt_data[i];
        }
        else{
            package->Type[i-12]=pkt_data[i];
        }
    }
    i++;
    //for(i;)
}




namespace sm
{
    namespace lbr
    {
        void printSomething()
        {
            std::cout << "Hello guys! " << std::endl;
        }
    }
}
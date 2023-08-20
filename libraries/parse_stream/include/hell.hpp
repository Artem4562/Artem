#ifndef HELL_H
#define HELL_H
#include <pcap.h>

typedef struct SV_Protocol{
    unsigned char *Destinatinion = new unsigned char[6];
    unsigned char *Source = new unsigned char[6];
    unsigned short Type; 
    unsigned short AppID; 
    unsigned short Lenght; 
    unsigned short Res1; 
    unsigned short Res2; 
    //int savapdu;
    unsigned char noAsdu;
    //int seqasdu;
    //int asdu;
    unsigned char *svID;
    unsigned short smpCnt;
    unsigned long confRef;
    unsigned char smpSynch;
    unsigned char Data[64];
}SV_PROT;

void func_rasb(char*  ,int  ,int , SV_PROT *);

void WildFox(const u_char *, pcap_pkthdr *, SV_PROT *);

namespace sm
{
    namespace lbr
    {
        void printSomething();
    }
}

#endif // HELL_H
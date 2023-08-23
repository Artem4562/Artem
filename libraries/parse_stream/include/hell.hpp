#ifndef HELL_H
#define HELL_H
#include <pcap.h>

typedef struct {
    unsigned char Destination[6];
    unsigned char Source[6];
    unsigned short Type; 
    unsigned short AppID; 
    unsigned short Lenght; 
    unsigned short Res1; 
    unsigned short Res2; 
    unsigned char noAsdu = 0;
    unsigned char *svID = new unsigned char;
    unsigned short smpCnt;
    unsigned long confRef;
    unsigned char smpSynch;
    // unsigned char Data[64];
    int Ia;
    int Ib;
    int Ic;
    int In;
    int Ua;
    int Ub;
    int Uc;
    int Un;
}SV_PROT;

void func_rasb(char*  , int  , int , SV_PROT *);

void WildFox(const u_char * , pcap_pkthdr * , SV_PROT *);

namespace sm
{
    namespace lbr
    {
        void printSomething();
    }
}

#endif // HELL_H
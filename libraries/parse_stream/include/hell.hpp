#ifndef HELL_H
#define HELL_H
#include <pcap.h>

#define  LEN_ETHERNET_ADDR  6           //lenght of MAC adress

typedef struct {
    unsigned char Destination[6];
    unsigned char Source[6];
    unsigned short Type; 
    unsigned short AppID; 
    unsigned short Lenght; 
    unsigned short Res1; 
    unsigned short Res2; 
    unsigned char noAsdu = 0;
    unsigned char *svID = new unsigned char[8];
    unsigned short smpCnt;
    unsigned long confRef;
    unsigned char smpSynch;
    int Ia;
    int Ib;
    int Ic;
    int In;
    int Ua;
    int Ub;
    int Uc;
    int Un;
}SV_PROT;

typedef struct {
    unsigned char Destination[6];
    unsigned char Source[6];
    unsigned short AppID;
    unsigned char *svID = new unsigned char[8];
    unsigned char id;
}SV_PROT_NF_I;

typedef struct {
    unsigned char Destination[6];
    unsigned char Source[6];
    unsigned short AppID;
    unsigned char *svID = new unsigned char[8];
}SV_PROT_F_I;



void WildFox(const u_char * , pcap_pkthdr * , SV_PROT *);


#endif // HELL_H
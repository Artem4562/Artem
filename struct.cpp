#include <iostream>
#include <conio.h>
using namespace std;





struct SV_Protocol 
{
    int i;
    short Destinatinion[7];
    for(i=0;i<7;i++ )//думаю, как-то так оно должно работать 
    {
        pkt_data[i].Destinatinion;
    }
    short Source[7];
    short *Type;
    short *AppID;
    unsigned short int Lenght;
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
};


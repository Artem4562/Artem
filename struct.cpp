#include <iostream>






struct SV_Protocol 
{
    int i = 0;
    short Destinatinion[7];
    for(i;i<7;i++ )//думаю, как-то так оно должно работать 
    {
        Destinatinion[i]=pkt_data[i];
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


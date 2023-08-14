#include <iostream>
#include <conio.h>
using namespace std;





struct SV_Protocol 
{
    short Destinatinion[7];
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


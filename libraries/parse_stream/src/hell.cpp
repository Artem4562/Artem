#include <iostream>
#include <pcap.h>

typedef struct SV_Protocol 
{
    unsigned char *Destinatinion= new unsigned char[7];
    unsigned char *Source = new unsigned char[7];
    unsigned short *Type;
    unsigned short *AppID;
    unsigned short Lenght;
    unsigned short *Res1;
    unsigned short *Res2;
    //int savapdu;
    unsigned char noAsdu;
    //int seqasdu;
    //int asdu;
    unsigned char *svID = new unsigned char;
    unsigned short smpCnt;
    unsigned long confRef;
    unsigned char smpSynch;
    unsigned char Data[65];
} SV_PROT;

void func_rasb(const u_char* pc ,int i ,int len_pc, SV_PROT *package){
    int len_triplet;
    len_triplet = pc[i];
    if(pc[i-1]<128 || pc[i-1]>136){
        func_rasb(pc,i+2,len_pc,package);
        if(len_pc - len_triplet - i - 1 !=0){
            func_rasb(pc,i+2+len_triplet,len_pc,package);
        }
    }
    if(pc[i-1]==128 && pc[i]==1) package->noAsdu = pc[i+1];
    else if(pc[i-1]==128){
        for(int j = i++; j<=len_triplet; j++){
            package->svID[j-i-1] = pc[j-1];
        } 
    } 
    if(pc[i-1]==130){
        package->smpCnt = (unsigned short)(pc[i++]<<8)|(pc[i++]);
    }
    if(pc[i-1]==131){
        for(int j = i++; j<=len_triplet; j++){
            package->confRef = (unsigned long)(pc[i++]<<8)|(pc[i++]);
        }
    }
    if(pc[i-1]==133) package->smpSynch = pc[i+1];
    if(pc[i-1]==131){
        for(int j = i++; j<=len_triplet; j++){
            package->Data[j-i-1] = pc[j-1];
        }
    }
}


void WildFox(const u_char *pkt_data, pcap_pkthdr *header, SV_PROT *package){
    int i;
    int len;
    for(i = 1; i<14;i++){
        if(i<=6){
            package->Destinatinion[i-1]=pkt_data[i-1];
        }
        else if(7<=i<=12){
            package->Source[i-7]=pkt_data[i-1];
        }
        else{
            package->Type=(unsigned short*)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
    }
    for(i++;i<22;i+=2){
        if(i==15){
            package->AppID=(unsigned short*)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
        if(i==17){
            package->Lenght=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
        if(i==19){
            package->Res1=(unsigned short*)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
        if(i==21){
            package->Res2=(unsigned short*)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
        
    }
    //i++;
    func_rasb(pkt_data,i++,header->len,package);
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
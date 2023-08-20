#include <iostream>
#include <pcap.h>
#include "hell.hpp"



void func_rasb(const u_char* pc ,int i ,int len_pc, SV_PROT *package){
    int len_triplet;
    len_triplet = pc[i];
    if(pc[i-1]<128 || pc[i-1]>136){
        func_rasb(pc,i+2,len_pc,package);
    }
    if(len_pc - len_triplet - i - 1 !=0){
            func_rasb(pc,i+2+len_triplet,len_pc,package);
        }
    if(pc[i-1]==128 && pc[i]==1) package->noAsdu = pc[i+1];
    else if(pc[i-1]==128){
        package->svID = new u_char[len_triplet];
        for(int j = i+1; j-i<=len_triplet; j++){
            package->svID[j-i-1] = pc[j];
        } 
    } 
    if(pc[i-1]==130){
        package->smpCnt = (unsigned short)(pc[i+1]<<8)|(pc[i+2]);
    }
    if(pc[i-1]==131){
        for(int j = i+1; j<=len_triplet; j++){
            package->confRef = (unsigned long)(pc[i+1]<<24)|(pc[i+2]<<16)|(pc[i+3]<<8)|(pc[i+4]);
        }
    }
    if(pc[i-1]==133) package->smpSynch = pc[i+1];
    if(pc[i-1]==135){
        for(int j = i+1; j-i<=len_triplet; j++){
            package->Data[j-i-1] = pc[j];
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
        else if(7<=i && i<=12){
            package->Source[i-7]=pkt_data[i-1];
        }
        else{
            package->Type=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
    }
    for(i++;i<22;i+=2){
        if(i==15){
            package->AppID=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
        if(i==17){
            package->Lenght=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
        if(i==19){
            package->Res1=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
        }
        if(i==21){
            package->Res2=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
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
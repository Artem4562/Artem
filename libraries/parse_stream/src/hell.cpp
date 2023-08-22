#include <iostream>
#include <pcap.h>
#include "hell.hpp"

#define  LEN_ETHERNET_ADDR  6           //lenght of MAC adress
#define  NO_ASDU_OR_SVID    0x80        //standart IEC 61850-8-1
#define  SMP_CNT            0x82        //standart IEC 61850-8-1
#define  CONF_REV           0x83        //standart IEC 61850-8-1
#define  SMP_SYNCH          0x85        //standart IEC 61850-8-1
#define  SEQ_OF_DATA        0x87        //standart IEC 61850-8-1
#define  CATALOG            0b00100000  //check for constractive type
#define  TRIPLET_SHIFT      2           //shift from type byte to first data byte
#define  LENGHT_SHIFT       1           //shift to compensate pointer on lenght for full package size 

void func_rasb(const u_char* pc ,int i ,int len_pc, SV_PROT *package){
    int len_triplet = pc[i];
    if( !(pc[i-1] & CATALOG) ){
        switch (pc[i-1])  //если () = чему-то после case
		{
			case NO_ASDU_OR_SVID:  //в случае чего если
			{
				if(package->noAsdu){
                    for(int j = i+1; j-i<=len_triplet; j++){
                        package->svID[j-i-1] = pc[j];
                    } 
                }
                else package->noAsdu = pc[i+1];
			};
			break;
			
			case SMP_CNT:
			{
				package->smpCnt = (unsigned short)(pc[i+1]<<8)|(pc[i+2]);
			};
			break;

			case CONF_REV:
			{
				package->confRef = (unsigned long)(pc[i+1]<<24)|(pc[i+2]<<16)|(pc[i+3]<<8)|(pc[i+4]);
			};
			break;

            case SMP_SYNCH:
			{
			    package->smpSynch = pc[i+1];
			};
			break;

            case SEQ_OF_DATA:
			{
				for(int j = i + LENGHT_SHIFT; j-i<=len_triplet; j++){
                    package->Data[j-i-1] = pc[j];
                }
			};
			break;
		}
    }

    else func_rasb( pc , i + TRIPLET_SHIFT , len_pc ,package );
        
    if(len_pc - len_triplet - i - LENGHT_SHIFT != 0)  func_rasb( pc , i + len_triplet + TRIPLET_SHIFT , len_pc , package );
    
}


void WildFox(const u_char *pkt_data, pcap_pkthdr *header, SV_PROT *package){
    int i;
    int len;
    for(i = 1; i <= LEN_ETHERNET_ADDR*2 ;i++){
        if(i <= LEN_ETHERNET_ADDR){
            package->Destination[i-1] = pkt_data[i-1];
        }
        else if(LEN_ETHERNET_ADDR < i && i <= LEN_ETHERNET_ADDR*2){
            package->Source[i-LEN_ETHERNET_ADDR-1] = pkt_data[i-1];
        }
    }

    for(;i<22;i+=2){
        switch(i)
        {
            case 13:
                {
                    package->Type=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
                };
			break;

            case 15:
                {
                    package->AppID=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
                };
			break;

            case 17:
                {
                    package->Lenght=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
                };
			break;

            case 19:
                {
                    package->Res1=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
                };
			break;

            case 21:
                {
                    package->Res2=(unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
                };
			break;
        }        
    }
    func_rasb(pkt_data,i++,header->len,package);
}





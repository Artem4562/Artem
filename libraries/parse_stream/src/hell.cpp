#include <iostream>
#include <pcap.h>
#include "hell.hpp"

#define  LEN_ETHERNET_ADDR  6           //lenght of MAC adress
#define  LEN_NON_TRIP       22          //lenght of none-triplet data
#define  NO_ASDU_OR_SVID    0x80        //standart IEC 61850-8-1
#define  SMP_CNT            0x82        //standart IEC 61850-8-1
#define  CONF_REV           0x83        //standart IEC 61850-8-1
#define  SMP_SYNCH          0x85        //standart IEC 61850-8-1
#define  SEQ_OF_DATA        0x87        //standart IEC 61850-8-1
#define  CATALOG            0b00100000  //check for constractive type
#define  TRIPLET_SHIFT      2           //shift from type byte to first data byte
#define  LENGHT_SHIFT       1           //shift to compensate pointer on lenght for full package size 
#define  NOMINAL_VALUE      4           //shift for parsing

void func_rasb(const u_char* pc ,int i ,int len_pc, SV_PROT *package){
    int len_triplet = pc[i];
    if( !(pc[i-1] & CATALOG) ){
        switch (pc[i-1]) 
		{
			case NO_ASDU_OR_SVID:  
			{
				if(package->noAsdu){
                    package->svID.clear();
                    for(int j = i; j-i<len_triplet; j++){
                        package->svID.push_back( pc[j+1]);
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
				package->confRef = (unsigned int)(pc[i+1]<<24)|(pc[i+2]<<16)|(pc[i+3]<<8)|(pc[i+4]);
			};
			break;

            case SMP_SYNCH:
			{
			    package->smpSynch = pc[i+1];
			};
			break;

            case SEQ_OF_DATA: 
			{   
                int *MAS[8] = {&package->Ia,&package->Ib,&package->Ic,&package->In,&package->Ua,&package->Ub,&package->Uc,&package->Un}; 

                for(int j = 0 , k = i + 1; k < len_pc-6; k+=8, j++){
                    *(MAS[j]) = (int)((pc[k]<<24)|(pc[k+1]<<16)|(pc[k+2]<<8)|(pc[k+3]));
                }
			};
			break;

		}
    }

    else func_rasb( pc , i + TRIPLET_SHIFT, len_pc ,package );
        
    if(len_pc - len_triplet - i - LENGHT_SHIFT - 6 != 0)  func_rasb( pc , i + len_triplet + TRIPLET_SHIFT , len_pc , package );
    
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

    unsigned short *MAS[5] = {&package->Type,&package->AppID,&package->Lenght,&package->Res1,&package->Res2};

    for(int j = 0; i < LEN_NON_TRIP; i+=2, j++){
        *(MAS[j]) = (unsigned short)((pkt_data[i-1]<<8)|(pkt_data[i]));
    }

    if (package->Type == 0x88ba) func_rasb(pkt_data,i++,header->len,package);
}





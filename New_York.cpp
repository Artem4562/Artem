#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <pcap.h>
#include <fstream>
#include <conio.h>


using namespace std;
#define LINE_LEN 16

static int count=0;

void callback(u_char *arg, const struct pcap_pkthdr* pkthdr, 
	const u_char* packet) 
{  
	count++;
	/*
	int i=0; 
	static int count=0; 

	printf("Packet Count: %d\n", ++count);             
	printf("Recieved Packet Size: %d\n", pkthdr->len); 
	printf("Payload:\n");                              
	for(i=0;i<pkthdr->len;i++) { 
		if(isprint(packet[i]))            
			printf("%c ",packet[i]);       
		else 
			printf(" . ",packet[i]);       
		if((i%16==0 && i!=0) || i==pkthdr->len-1) 
			printf("\n"); 
	}
	*/
}



int main(int argc, char **argv){
	string path ="C:\\Users\\mrsic\\Documents\\GitHub\\Artem\\name.txt";
	ifstream fin;
    char *str = new char;
	fin.open(path);
	if (!fin.is_open()){
		cout<< "FATAL ERROR"<< endl;
	}
	else {
        cout<< "file is open!"<<endl;
        fin.getline(str, 256,'\n');
        cout<<endl;
		
    
		fin.close();
	

		pcap_t *fp;
		char errbuf[PCAP_ERRBUF_SIZE] = {0};
		int i;
		struct bpf_program fcode;
		int res;
		bpf_u_int32 mask;   /* Сетевая маска устройства */
		bpf_u_int32 net;	/* IP устройства */

		

		if ( (fp= pcap_open_live(str,
								BUFSIZ /*snaplen*/,
								1 /*flags*/,
								1000 /*read timeout*/,
								errbuf)
								) == NULL)
			{
				cout<<"\nError opening adapter: "<< errbuf <<'\n';
				getch();
				return -1;
			}
		else // open ok
		{	
			pcap_lookupnet(str, &net, &mask, errbuf);
			if((res = pcap_compile(fp, &fcode, "apa", 1, mask)) < 0)
				{
					cout<<"\nError compiling filter: "<< res <<'\n';
					getch();
					pcap_close(fp);
					return -3;
				}

				//set the filter
			if((res = pcap_setfilter(fp, &fcode))<0)
				{
					cout<<"\nError setting the filter: "<< res <<'\n';
					getch();
					pcap_close(fp);
					return -4;
				}

			cout<<"Recieved Packet Size:   ";
			while(pcap_dispatch(fp,-1,callback,NULL)>=0){
				cout<<string ( to_string(count).length(),'\b'); 
				cout<<count;
				count=0;
			}

		}	 	
		getch();
	}
}


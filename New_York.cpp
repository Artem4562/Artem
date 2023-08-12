#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <pcap.h>
#include <fstream>
#include <conio.h>
#include <ctime>



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
	ifstream fin;     //определяю новый поток ввода/вывода потока данных
    char *str = new char;
	fin.open(path);
	if (!fin.is_open()){
		cout<< "FATAL ERROR"<< endl;
		getch();
	}
	else {
        cout<< "file is open!"<<endl;
        fin.getline(str, 256,'\n');
        cout<<endl;
		
    
		fin.close();
		
		const u_char* pkt_data;
		struct pcap_pkthdr *header;
		pcap_t *fp;  //дескриптор (радиостанция)
		char errbuf[PCAP_ERRBUF_SIZE] = {0};
		struct bpf_program fcode;     //переменная для записи фильтра
		int res;  //переменная под ошибки 
		bpf_u_int32 mask;   /* Сетевая маска устройства */
		bpf_u_int32 net;	/* IP устройства */
		bool flag = true;
		time_t time_start;
		float razn;
		
		

		if ( (fp= pcap_open_live(str,
								65535 /*snaplen*/,
								1 /*flags*/,   //в каком режиме это слушаем
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
			pcap_lookupnet(str, &net, &mask, errbuf);     // записывает в mask и net маску адаптера и ip адаптера 
			if((res = pcap_compile(fp, &fcode, "ip", 1, mask)) < 0) //составление фльтра 
				{
					cout<<"\nError compiling filter: "<< res <<'\n';
					getch();
					pcap_close(fp);
					return -3;
				}

				//set the filter
			if((res = pcap_setfilter(fp, &fcode))<0)   //применение фильтра 
				{
					cout<<"\nError setting the filter: "<< res <<'\n';
					getch();
					pcap_close(fp);
					return -4;
				}

			cout<<"Recieved Packet Size:                                         ";
			/*while(pcap_dispatch(fp,-1,callback,NULL)>=0){      //при ловле пакета срабатывает ф-ция callback
				cout<<string ( to_string(count).length(),'\b'); 
				cout<<count;
				count=0;
			}*/
			
			while(true)
			{ 	
				time_start= time(0);
				while((razn=time(0)-time_start)<1 && (res = pcap_next_ex( fp, &header, &pkt_data)) >= 0   )
            	{
                	if(res == 0)
                	/* Timeout elapsed */
                	continue;
					count++;
					

           		}
				cout<<string ( to_string(count).length() + 36,'\b');
				fprintf(stderr,"%d time: %.5f localtime: %d",count,razn,time(0));
				count=0;
				flag= true;
				time_start = time(0);
			
			}
			
		}	 	
		getch();
	}
	fin.close();
}


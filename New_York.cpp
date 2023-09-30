#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <pcap.h>
#include <fstream>
#include <conio.h>
#include <ctime>
#include <iomanip>



using namespace std;
#define LINE_LEN 16

typedef struct {
	long count_for_timestamp = 0;
	long current_time = 0;
	long counter = 0;
} counter;

static counter c;

static int count=0;

void callback(u_char *arg, const struct pcap_pkthdr* pkthdr, 
	const u_char* packet) 
{  
	c.current_time = time(0);
	if (c.current_time-c.count_for_timestamp>1){
		cout<<string ( to_string(c.counter).length() + 3 + to_string(count).length(),'\b'); 
		cout<<c.counter<<"   "<<count;
		c.counter = 0;
		c.count_for_timestamp = c.current_time;
	}
	c.counter++;
	count++;
}



int main(int argc, char **argv){


	string path ="../name.txt";
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
		double razn;
		
		

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
			if((res = pcap_compile(fp, &fcode, "ether dst 01:0c:cd:04:00:10", 1, mask)) < 0) //составление фльтра 
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

			cout<<"Recieved Packet Size:           ";
			while(pcap_dispatch(fp,-1,callback,NULL)>=0){      //при ловле пакета срабатывает ф-ция callback
			}
			
			
			
		}	 	
		getch();
	}
	fin.close();
}


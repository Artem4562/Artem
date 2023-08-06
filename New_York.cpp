#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <pcap.h>
#include <fstream>
#include <conio.h>


using namespace std;
#define LINE_LEN 16

int main(int argc, char **argv){
	string path ="C:/Users/User/Documents/GitHub/Artem/name.txt";
	ifstream fin;
    char* str = NULL;
	fin.open(path);
	if (!fin.is_open()){
		cout<< "FATAL ERROR"<< endl;
	}
	else {
        cout<< "file is open!"<<endl;
        int i=0; 
		/*while(!fin.eof())
        {
            fin.get(str[i]);
            i++;
        }*/
       	while((*str++=getchar ()) != '\n');
		*str = '\0';
        cout<<endl;
		
    }
	fin.close();
    getch();
}
    

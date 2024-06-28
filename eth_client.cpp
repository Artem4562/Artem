#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <ncurses.h>


using namespace std;
typedef struct UI{
    pthread_mutex_t mutex_UI;
    int port_own,  port_sender;
    int bytesRead, bytesWritten;
    int clientSd;
    int serverSd;
    int newSd;
    bool flag = true;
    int argc;
    char ** argv;
    int Errno;
    int *Err = &Errno;
    char * mess = new char;
} UI;


void * recive_data (void * argn){
    UI * arg = (UI*) argn;
    //we need 2 things: ip address and port number, in that order
    if(arg->argc != 3)
    {
        cerr << "Usage: ip_address port" << endl; exit(0); 
    } //grab the IP address and port number 
    char *serverIp = arg->argv[1]; int port = atoi(arg->argv[2]); 
    //create a message buffer 
    char msg[1500]; 
    //setup a socket and connection tools 
    struct hostent* host = gethostbyname(serverIp); 
    sockaddr_in sendSockAddr;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = 
        inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    //try to connect...
    int status = connect(clientSd,
                         (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    if(status < 0)
    {
        cout<<"Error connecting to socket!"<<endl;
    }
    //cout << "Connected to the server!" << endl;
    int bytesRead, bytesWritten = 0;
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);
    //cout << "Awaiting server response..." << endl;
    while(1)
    {
        
        
        
        bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
        if(!strcmp(msg, "exit"))
        {
            cout << "Server has quit the session" << endl;
            break;
        }
        arg->mess = msg;
        //printw("Server: %s",msg);
        memset(&msg, 0, sizeof(msg));//clear the buffer
    }
    gettimeofday(&end1, NULL);
    close(clientSd);
    cout << "********Session********" << endl;
    cout << "Bytes written: " << bytesWritten << 
    " Bytes read: " << bytesRead << endl;
    cout << "Elapsed time: " << (end1.tv_sec- start1.tv_sec) 
      << " secs" << endl;
    cout << "Connection closed" << endl;
    return 0;    
}

void * send_data (void * argv){
    UI * arg = (UI*) argv;
    char msg[1500];
    sleep(1);
    while(false){
        string data;
        cout<<"Type message:";
        //getline(cin, data);
        strcpy(msg, data.c_str());
        if(data == "exit")
        {
            //send to the client that server has closed the connection
            send(arg->clientSd, (char*)&msg, strlen(msg), 0);
            arg->flag = false;
            break;
        }
        //send the message to client
        arg->bytesWritten += send(arg->clientSd, (char*)&msg, strlen(msg), 0);
        memset(&msg, 0, sizeof(msg)); //clear the buffer
    }

    return 0;
}

void * CURSE(void *argv){
    UI * arg = (UI*) argv;

    // инициализация (должна быть выполнена 
    // перед использованием ncurses)
    initscr();

    // Измеряем размер экрана в рядах и колонках
    printw("Heee"); // вывод строки
    while(1){
        printw("%s",arg->mess);
        move(0,0);
        refresh(); // обновить экран
    }
     
    
    getch(); // ждём нажатия символа
    
    endwin(); // завершение работы с ncurses
    return 0;
}

//Client side
int main(int argc, char *argv[])
{
    
    UI com;
    pthread_t recive_command, send_d, monitor;
    com.argc = argc;
    com.argv = argv;


    pthread_create(&recive_command, NULL, *recive_data, (void *) &com);
    pthread_create(&monitor, NULL, *CURSE, (void *) &com);
    //pthread_create(&send_d, NULL, *send_data, (void *) &com);
    pthread_mutex_init(&(com.mutex_UI), NULL);
    pthread_join(recive_command, NULL);
    pthread_join(monitor, NULL);
    //pthread_join(send_d, NULL);

    
    return 0;    
}
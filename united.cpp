#include <iostream>
#include <vector>
#include <hell.hpp>
#include <pcap.h>
#include <math.h>
#include <iomanip>
#include <algorithm>
#include <string>
#include <DFT.hpp>
#include <time.h>
#include <unistd.h>
#include "libraries/glfw/deps/glad/gl.h"
#include <GLFW/glfw3.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <imgui.h>
#include <implot.h>
#include <implot_internal.h>

using namespace std;

#define GLFW_INCLUDE_NONE
#define GLAD_GL_IMPLEMENTATION
#define _USE_MATH_DEFINES
#define LINE_LEN 16



void (*dispatcher) (u_char *, const struct pcap_pkthdr *, const u_char *);
void dispatcher_handler1(u_char *, const struct pcap_pkthdr *, const u_char *);
void dispatcher_handler2(u_char *, const struct pcap_pkthdr *, const u_char *);


static SV_PROT_AMP datat;
static bool flg = false;
static bool fg = false;
static bool flag = false;
static int id =0;
static int kek=0;
static int MINUA=0;
static std::vector<SV_PROT_D> Result;

void * receive(void * DataKrat){	
    for (;;){
    int argc
    char **argv
	// accept signal from VSCode for pausing/stopping
    char *sudo_uid = getenv("SUDO_UID");
    if (sudo_uid)
        setresuid(0, 0, atoi(sudo_uid));

    printf("uid = %d\n", getuid());



	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	struct bpf_program fcode;     //переменная для записи фильтра
	int res;  //переменная под ошибки 
	bpf_u_int32 mask;   /* Сетевая маска устройства */
	bpf_u_int32 net;	/* IP устройства */
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	int inum;

	std::cin>>(kek);
	    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(dev=alldevs; dev; dev=dev->next)
    {
        printf("%d. %s", ++i, dev->name);
        if (dev->description)
            printf(" (%s)\n", dev->description);
        else
            printf(" (No description available)\n");
    }
    
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    std::cin>>(inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* Jump to the selected adapter */
    for(dev=alldevs, i=0; i< inum-1 ;dev=dev->next, i++);
    
    /* Open the device */
    if ( (fp= pcap_open_live(dev->name,         // name of the device
                              65536,            // portion of the packet to capture. 
                              true,             // 65536 guarantees that the whole packet will be captured on all the link layers
                              1000,             // read timeout            
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
		std::cout<<'\n'<<errbuf;
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

	if (pcap_datalink(fp) != DLT_EN10MB) 
		{
			fprintf(stderr, "Device %s doesn't provide Ethernet headers -not  supported\n", dev->name);
			return(2);
		}

	if((res = pcap_compile(fp, &fcode, "not udp and not ip and ether[12]=136 and ether[13]=186", 1, 0)) < 0) //составление фльтра 
		{	
			cout<<"\nError compiling filter: "<< res <<'\n';
			pcap_close(fp);
			return -3;
		}

		//set the filter
	if((res = pcap_setfilter(fp, &fcode))<0)   //применение фильтра 
		{
			cout<<"\nError setting the filter: "<< res <<'\n';
			pcap_close(fp);
			return -4;
		}

    
    printf("\nlistening on %s...\n", dev->name);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    
	if(!kek) dispatcher = dispatcher_handler1; 
	else dispatcher = dispatcher_handler2;
	pcap_loop(fp,0,dispatcher,NULL);
	
	pcap_close(fp);
	return 0;
    }
}

void dispatcher_handler1(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
	
	SV_PROT prot;
	SV_PROT_NF_I data;
	bool flg = false;
	int j = 0;
	WildFox(pkt_data,header, &prot);
	while(!flg && j<id){
		if(prot.AppID==DataKrat[j].AppID ) flg=true;
		j++;
	}
    pthread_mutex_lock(&(extd->mutex));
	if(!DataKrat.size() || !flg){
		data.AppID = prot.AppID;
		copy_n(prot.Destination, sizeof(prot.Destination), data.Destination);
		copy_n(prot.Source, sizeof(prot.Source), data.Source);
		data.svID = prot.svID;
		data.id = id++;
		DataKrat.push_back(data);
	}	
    pthread_mutex_unlock(&(extd->mutex));
	
}

void dispatcher_handler2(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){	
	SV_PROT prot;
	WildFox(pkt_data,header, &prot);
	if(prot.AppID == kek ){
		if(MINUA==0 && MINUA>prot.Ua && !fg){
			MINUA=prot.Ua;
		}
		if(MINUA>prot.Ua && !fg){
			MINUA=prot.Ua;
			flag= true;
		}
		if(MINUA<prot.Ua && flag== true && !fg){
			fg= true;
		}

		if(!flg && fg && 0.001>(abs(float(prot.Ua)/MINUA))){
			flg = true;
		}

		if(flg){
			datat.push_back_prot(prot);
		}
		if(datat.size()==800){
			DFT_4000D_1S(800,datat,LOWPERF,&Result);
			datat.erase_prot_all();
		
			
		}
	}
}
// -------------------------------------------------------------------------------------------------------------------


vector<char> t = {'N','G','r','i','d','_','c','a','b','l','e','_','1'};
    


bool *flag = new bool; 
static int k=0; // для кнопок в Streams_Sv
static unsigned short f = 0; // для APP_ID в Streams_SV
static int s; // для вызова WindowFullInformation

string SVinfo(int Stream_number, char* SV_ID, unsigned short APP_ID, unsigned char MAC[6]){   
    string D;
    string info = "";
    const char *ch; 
    for(int i=0;i<6;i++){
        D += to_string(MAC[i]);
        if (i<5) D+=':';
    }
    std::cout<<info<<"Nach\n\n";
    info += "Stream_number: " + to_string(Stream_number) + "\nSV_ID: " + SV_ID + "\nAPP_ID: " + to_string(APP_ID) + "\nMAC: " + D +"\n" ;

    return info;
}

void WindowFullInformation(int id,char* svID,unsigned short APP_ID, unsigned char MAC[6]) {
    string D ="";
    for(int i=0;i<6;i++){
        D += to_string(MAC[i]);
        if (i<5) D+=':';
    }
    
    ImGui::SetNextWindowPos(ImVec2(0, 0));    
    ImGui::SetNextWindowSize(ImVec2(480,800));
    ImGui::Begin("Full_Information_to_SV",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar);
    ImGui::SetWindowFontScale(1.5f);
    ImVec2 sizewindow = ImGui::GetWindowSize();
    ImVec2 sizetext = ImGui::CalcTextSize("Streams SV");
    float posX = (sizewindow.x - sizetext.x) * 0.5f;
    ImGui::SetCursorPosX(posX);
    ImGui::Text("Streams SV");
    ImVec2 sizetextX = ImGui::CalcTextSize("Stream # XX");
    posX=(sizewindow.x - sizetextX.x) * 0.5f;
    ImGui::SetCursorPosX(posX);
    ImGui::Text("Stream # %d",id+1);
    ImGui::SetCursorPosX(0.0f);

    if (ImGui::Button("Return to the list of streams", ImVec2(480, 50))) f = 0;

    ImGui::Text("SV_ID: %s", svID);
    ImGui::Text("APP_ID: %d", APP_ID);
    ImGui::Text("MAC: %s", D.c_str());
    
    
    int Ia = 4678;
    int Ib = 2023;
    int Ic = 7698;
    int In = 2288;
    int Ua = 1520;
    int Ub = 1337;
    int Uc = 3654;
    int Un = 5436;

    ImVec2 cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(139, 69, 19, 200));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("Ua= %d;",Ua);

    cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 0, 255));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("Ub= %d;",Ub);

    cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(128, 128, 128, 255));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("Uc= %d;",Uc);

    cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 128, 255));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("Un= %d;",Un);

    cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(139, 69, 19, 200));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("Ia= %d;",Ia);

    cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 0, 255));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("Ib= %d;",Ib);

    cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(128, 128, 128, 255));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("Ic= %d;",Ic);

    cursorpos = ImGui::GetCursorPos();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 128, 255));
    ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
    ImGui::Text("In= %d;",In);

    ImGui::SetWindowFontScale(1.0f);
    
    if(ImPlot::BeginPlot("Graph I", ImVec2(300,300))){
        float Iax[2]={0.0, 1.0};
        float Iay[2]={0.0, 1.0};
        ImPlot::PlotLine("Ia",Iax, Iay, 2);

        float Ibx[2]={0.0, 0.2};
        float Iby[2]={0.0, 0.1};
        ImPlot::PlotLine("Ib",Ibx, Iby, 2);

        float Icx[2]={0.0, -1.5};
        float Icy[2]={0.0, -0.5};
        ImPlot::PlotLine("Ic",Icx, Icy, 2);

        float Inx[2]={0.0, -1.0};
        float Iny[2]={0.0, 1.0};
        ImPlot::PlotLine("In",Inx, Iny, 2);

        ImPlot::EndPlot(); 
    }
    ImGui::End();
}

void Streams_SV(bool *flag){
    ImGui::SetNextWindowPos(ImVec2(0,0));
    ImGui::SetNextWindowSize(ImVec2(480,800));
    ImGui::Begin("Streams SV",  nullptr,  ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove
    | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::SetWindowFontScale(1.5f);
    ImVec2 sizewindow = ImGui::GetWindowSize();
    ImVec2 sizetext = ImGui::CalcTextSize("Streams SV");
    float posX = (sizewindow.x - sizetext.x) * 0.5f;
    ImGui::SetCursorPosX(posX);
    ImGui::Text("Streams SV ");
    ImVec2 sizetextX = ImGui::CalcTextSize("XX streams detected");
    float posXX = (sizewindow.x - sizetextX.x) * 0.5f;
    ImGui::SetCursorPosX(posXX);
    ImGui::Text("%d streams detected ",int(DataKrat.size()));
    ImGui::SetCursorPosX(0.0f);

    ImGui::SetWindowFontScale(1.5f);
    if (ImGui::Button("Return to the main menu", ImVec2(480, 50))) 
        flag[0] = false;
    ImGui::SetWindowFontScale(1.0f);
    ImGui::SetCursorPosX(0.0f);
    ImGui::SetWindowFontScale(1.5f);
   
    for( int i=6*k ; i < DataKrat.size() && i < 6*k+6 ;i++){
        ImGui::SetCursorPosX(0.0f);
        ImGui::SetWindowFontScale(1.5f);
        if (ImGui::Button(&SVinfo(i+1,&(a[i].svID)[0], a[i].AppID, a[i].Destination)[0], ImVec2(480, 100))) {
            f=a[i].AppID;
            s=i;
            
        }
        
    }
    
    if (k>0){
        ImGui::SetWindowFontScale(2.5f);    
        ImGui::SetCursorPos(ImVec2(0, 732));
        if (ImGui::Button("<", ImVec2(235, 50))) k -= 1;
        ImGui::SetWindowFontScale(1.0f);
    }

    if (6*k<(DK.size()-6)){
        ImGui::SetWindowFontScale(2.5f);
        ImGui::SetCursorPos(ImVec2(240, 732));
        if (ImGui::Button(">", ImVec2(245, 50))) k += 1;
        ImGui::SetWindowFontScale(1.0f);
    }

    ImGui::End();
}

void Main_Menu(bool *flag){
    ImGui::SetNextWindowPos(ImVec2(0,0)); // Указывает конкретную область, в которой должно появиться окно
    ImGui::SetNextWindowSize(ImVec2(480,800));
    ImGui::Begin("Main Menu",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize );
    ImVec2 sizewindow = ImGui::GetWindowSize();
    ImVec2 sizetext = ImGui::CalcTextSize("Main Menu");
    float posX = (sizewindow.x - sizetext.x) * 0.5f;
    ImGui::SetCursorPosX(posX);

    ImGui::SetWindowFontScale(1.5f);
    ImGui::Text("Main Menu");
    if (ImGui::Button("Streams SV", ImVec2(480, 100))) flag[0] = true; 
    if (ImGui::Button("Streams GOOSE", ImVec2(480, 100))) flag[1] = true;
    // if (flag[1]) Streams_GOOSE(flag);
    if (ImGui::Button("Generator SV", ImVec2(480, 100))) flag[2] = true;
    // if (flag[2]) Generator_SV(flag);
    if (ImGui::Button("Generator GOOSE", ImVec2(480, 100))) flag[3] = true;
    // if (flag[3]) Generator_GOOSE(flag);
    ImGui::SetWindowFontScale(1.0f);


    const char* labels[] = { "A", "B", "C", "D" };
    double values[] = { 25.0, 35.0, 20.0, 20.0 };

    
    ImGui::End();
} 

void * draw(void* DataKrat){
    for (;;){
    
    pthread_mutex_lock(&(extd->mutex));
    SV_PROT_NF_I* a = &DataKrat[0];
    pthread_mutex_unlock(&(extd->mutex));
    flag[0]=false;
    flag[1]=false;
    flag[2]=false;
    flag[3]=false;
    
    //FreeConsole();

    //Инициализация библиотеки GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW\n";
        return EXIT_FAILURE;
    }
    //Создаю окно 
    GLFWwindow* window = glfwCreateWindow(480, 800, "My window", NULL, NULL);
    if (!window) {
        glfwTerminate();
        return -1;
    }

    // Создание контекста OpenGL
    glfwMakeContextCurrent(window);
    //Что это не знаю, но без него не работает(
    gladLoadGL(glfwGetProcAddress);
    //Частота обновления кадров в приложении такая же, как у монитора
    glfwSwapInterval(1);

    //Инициализация ImGui и Implot
    ImGui::CreateContext();
    ImPlot::CreateContext();

    float red = (float)0x19 / 255.0f;
    float green = (float)0x19 / 255.0f;
    float blue = (float)0x70 / 255.0f;
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg] = ImVec4(red, green , blue, 0.5f); // Красный цвет фона окна
    //Инициализация ImGui для работы с библиотекой GLFW и OpenGL
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    //Инициализация ImGui для работы с OpenGL версии 3.3
    ImGui_ImplOpenGL3_Init("#version 130");

    while (!glfwWindowShouldClose(window)) { //Цикл будет выполняться пока окно не закроется
        glfwPollEvents();//Обрабатывает все события, которые происходят в окне и позволяет реагировать на них

        //Готовят imGui к отрисовке нового кадра в пользовательском интерфейсе
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        
        // Вызывает функцию
        if (!flag[0] && !flag[1] && !flag[2] && !flag[3] && f==0) Main_Menu(flag);
        if (flag[0] && f==0) Streams_SV(flag);
        if (f!=0){
            WindowFullInformation(s,&(a[s].svID)[0],f, a[s].Destination);
        }

        //Завершает отрисовку интерфейса и выводит на экран результат
        ImGui::Render();

        //Очищает буфер кадра, обычно для подготовки его к отрисовке нового кадра.
        glClear(GL_COLOR_BUFFER_BIT);

        //Рисует данные пользовательского интерфейса ImGui на текущем буфере кадра OpenGL
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        //Меняет местами буферы кадра GLFW, чтобы отобразить новый кадр на экране.
        glfwSwapBuffers(window);
    }
    //Освобождает все выделенные ресурсы, связанные с GLFW и завершает работу этой библиотеки 
    ImPlot::DestroyContext();
    glfwTerminate();
    }
}


// -------------------------------------------------------------------------------------------------------------------


int main(){
    pthread_t sv_receive, draw_graphics;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    vector<SV_PROT_NF_I> DataKrat;
    DataKrat.mutex = mutex;

    pthread_create(&sv_receive, NULL, *receive, (void *) &DataKrat);
    pthread_create(&draw_graphics, NULL, *draw, (void *) &DataKrat);
    pthread_join(sv_receive, NULL);
    pthread_join(draw_graphics, NULL);
}
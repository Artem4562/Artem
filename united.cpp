#include <iostream>
#include <vector>
#include <hell.hpp>
#include <pcap.h>
#include <algorithm>
#include <string>
#include <DFT.hpp>
#include <time.h>
#include <unistd.h>
#include <GL/gl.h>
#include <GLFW/glfw3.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <imgui.h>
#include <implot.h>
#include <implot_internal.h>
#include <pthread.h>
#include <fstream>
#include <queue>
#include <thread_manager.hpp>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"



using namespace std;


typedef struct{

    command_manager * com;
    
    bool flag[4]; 
    int k=0; // для кнопок в Streams_Sv
    unsigned short APP_ID = 0; // для APP_ID в Streams_SV
    int id; // для вызова WindowFullInformation
    
    int my_image_width = 0;
    int my_image_height = 0;
    GLuint my_image_texture = 0;



    string SVinfo(int I,vector<SV_PROT_NF_I> * DataKrat){   
        string ID;
        string info = "hello";
        const char *ch; 
        for(int i=0;i<(*DataKrat)[I].svID.size();i++){
            ID += (*DataKrat)[I].svID[i];
        }

        //info += "Stream_number: " + to_string(I+1) + "\nSV_ID: " + ID + "\nAPP_ID: " + to_string((*DataKrat)[I].AppID) + "\nMAC: " + (*DataKrat)[I].Destination +"\n" +(*DataKrat)[I].cnt_str ;
        return info;
    }

    void WindowFullInformation() {
        

        vector<SV_PROT_NF_I> * DataKrat = com->DataKrat;

        vector <char> svID = (*DataKrat)[id].svID;
        string MAC = (*DataKrat)[id].Destination;


        string ID ="";
        vector<vector<SV_PROT_D>> * DataFull = com->DataFull;
        for(int i=0;i<svID.size();i++){
            ID += svID[i];
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

        if (ImGui::Button("Return to the list of streams", ImVec2(480, 50))) APP_ID = 0;

        ImGui::Text("SV_ID: %s", ID.c_str());
        ImGui::Text("APP_ID: %d", APP_ID);
        ImGui::Text("MAC: %s", MAC.c_str());
        

        ImVec2 cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(139, 69, 19, 200));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("Ua= %6.0f<%3.2f;",(*DataFull)[id].back().Ua.NORM,(*DataFull)[id].back().Ua.ANGLE);

        cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 0, 255));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("Ub= %6.0f<%3.2f;",(*DataFull)[id].back().Ub.NORM,(*DataFull)[id].back().Ub.ANGLE);

        cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(128, 128, 128, 255));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("Uc= %6.0f<%3.2f;",(*DataFull)[id].back().Uc.NORM,(*DataFull)[id].back().Uc.ANGLE);

        cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 128, 255));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("Un= %6.0f<%3.2f;",(*DataFull)[id].back().Un.NORM,(*DataFull)[id].back().Un.ANGLE);

        cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(139, 69, 19, 200));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("Ia= %6.0f<%3.2f;",(*DataFull)[id].back().Ia.NORM,(*DataFull)[id].back().Ia.ANGLE);

        cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 0, 255));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("Ib= %6.0f<%3.2f;",(*DataFull)[id].back().Ib.NORM,(*DataFull)[id].back().Ib.ANGLE);

        cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(128, 128, 128, 255));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("Ic= %6.0f<%3.2f;",(*DataFull)[id].back().Ic.NORM,(*DataFull)[id].back().Ic.ANGLE);

        cursorpos = ImGui::GetCursorPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(15,cursorpos.y+5), 7, IM_COL32(0, 0, 128, 255));
        ImGui::SetCursorPos(ImVec2(25,cursorpos.y-5));
        ImGui::Text("In= %6.0f<%3.2f;",(*DataFull)[id].back().In.NORM,(*DataFull)[id].back().In.ANGLE);

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

    void Streams_SV(){
        vector<SV_PROT_NF_I> * DataKrat = com->DataKrat;
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
        ImGui::Text("%d streams detected ",int((*DataKrat).size()));
        ImGui::SetCursorPosX(0.0f);

        ImGui::SetWindowFontScale(1.5f);
        if (ImGui::Button("Return to the main menu", ImVec2(480, 50))){
            com->command_queue.push(SV_close);
            pthread_cond_broadcast(&com->queue_waiter);

            flag[0] = false; 
            
             
            
        }
        ImGui::SetWindowFontScale(1.0f);
        ImGui::SetCursorPosX(0.0f);
        ImGui::SetWindowFontScale(1.5f);
    
            for( int i=6*k ; i < (*DataKrat).size() && i < 6*k+6 ;i++){
                ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.1, 0.0));
                ImGui::SetCursorPosX(0.0f);
                ImGui::SetWindowFontScale(1.5f);
                if (ImGui::Button(&SVinfo(i,DataKrat)[0], ImVec2(480, 110))) {
                    //APP_ID=(*DataKrat)[i].AppID;
                    //id=i;
                    
                }
                
                ImU32 color = IM_COL32(0, 0, 0, 0);

                switch ((*DataKrat)[i].signal)
                {
                    case Red:
                    color = IM_COL32(255, 0, 0, 255); // красный
                    break;
                    case Gray:
                    color = IM_COL32(20, 20, 20, 255); // серый
                    break;
                    case Yellow:
                    color = IM_COL32(255, 255, 0, 255); // жёлтый 
                    break;
                    case Green:
                    color = IM_COL32(0, 255, 0, 255); // зелёный
                    break;
                }
                
                //ImU32 color =IM_COL32(255, 0, 0, 255);
                // Отрисовка кружочка
                ImVec2 buttonPos = ImGui::GetItemRectMin();
                ImVec2 buttonSize = ImGui::GetItemRectSize();
                // Выберите координаты для кружочка, например, справа от кнопки
                ImVec2 circlePos(buttonPos.x + buttonSize.x - 15, buttonPos.y + buttonSize.y - 20);
                ImGui::GetWindowDrawList()->AddCircleFilled(circlePos, 10, color); // Рисуем кружочек
                
                ImGui::PopStyleVar();
            }
        
        if (k>0){
            ImGui::SetWindowFontScale(2.5f);    
            ImGui::SetCursorPos(ImVec2(0, 732));
            if (ImGui::Button("<", ImVec2(235, 50))) k -= 1;
            ImGui::SetWindowFontScale(1.0f);
        }

        if (k<((*DataKrat).size()/6)){
            ImGui::SetWindowFontScale(2.5f);
            ImGui::SetCursorPos(ImVec2(240, 732));
            if (ImGui::Button(">", ImVec2(245, 50))) k += 1;
            ImGui::SetWindowFontScale(1.0f);
        }

        ImGui::End();
    }

    void Main_Menu(){
        ImGui::SetNextWindowPos(ImVec2(0,0)); // Указывает конкретную область, в которой должно появиться окно
        ImGui::SetNextWindowSize(ImVec2(480,800));
        ImGui::Begin("Main Menu",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize );
        ImVec2 sizewindow = ImGui::GetWindowSize();
        ImVec2 sizetext = ImGui::CalcTextSize("Main Menu");
        float posX = (sizewindow.x - sizetext.x) * 0.5f;
        ImGui::SetCursorPosX(posX);

        ImGui::SetWindowFontScale(1.5f);
        ImGui::Text("Main Menu");
        if (ImGui::Button("Streams SV", ImVec2(480, 100))){

            com->command_queue.push(SV_open);
            pthread_cond_broadcast(&com->queue_waiter);
            flag[0] = true; 
            
        } 
        if (ImGui::Button("Streams GOOSE", ImVec2(480, 100))) flag[1] = false;
        // if (flag[1]) Streams_GOOSE(flag);
        if (ImGui::Button("Generator SV", ImVec2(480, 100))) flag[2] = false;
        // if (flag[2]) Generator_SV(flag);
        if (ImGui::Button("Generator GOOSE", ImVec2(480, 100))) flag[3] = false;
        // if (flag[3]) Generator_GOOSE(flag);

        ImGui::Image((void*)(intptr_t)my_image_texture, ImVec2(my_image_width, my_image_height));
        ImGui::SetWindowFontScale(1.0f);


        const char* labels[] = { "A", "B", "C", "D" };
        double values[] = { 25.0, 35.0, 20.0, 20.0 };

        
        ImGui::End();
    }

    

}Display;


bool LoadTextureFromFile(const char* filename, GLuint* out_texture, int* out_width, int* out_height)
{
    // Load from file
    int image_width = 0;
    int image_height = 0;
    unsigned char* image_data = stbi_load(filename, &image_width, &image_height, NULL, 4);
    if (image_data == NULL)
        return false;

    // Create a OpenGL texture identifier
    GLuint image_texture;
    glGenTextures(1, &image_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);

    // Setup filtering parameters for display
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE); // This is required on WebGL for non power-of-two textures
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE); // Same

    // Upload pixels into texture
#if defined(GL_UNPACK_ROW_LENGTH) && !defined(__EMSCRIPTEN__)
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
#endif
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image_width, image_height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
    stbi_image_free(image_data);

    *out_texture = image_texture;
    *out_width = image_width;
    *out_height = image_height;

    return true;
} 

typedef struct packet_handler{
    pthread_mutex_t mutex_DK;
    int id = 0;
    std::vector<shiftUA> Shift;
    std::vector<SV_PROT_NF_I> DataKrat;
    std::vector<SV_PROT_AMP> DataD;
    std::vector<std::vector<SV_PROT_D>> DataFull;

    

    void dispatcher_handler1(u_char *temp1, 
						    const struct pcap_pkthdr *header, 
						    const u_char *pkt_data)
    {
        
        SV_PROT prot;
        bool flg = false;
        int j = 0;
        WildFox(pkt_data,header, &prot);
        while(!flg && j<id){
            if(prot.AppID==DataKrat[j].AppID ){
                flg=true;
                pthread_mutex_lock(&mutex_DK);
                DataKrat[j].smt_counter++;
                pthread_mutex_unlock(&mutex_DK);
                          
            } 
            j++;
        }
        if(!DataKrat.size() || !flg){
            pthread_mutex_lock(&mutex_DK);
            DataKrat.push_back(fill(prot,id++));
            pthread_mutex_unlock(&mutex_DK);

            SV_PROT_AMP DataD_T;
            DataD.push_back(DataD_T);
            std::vector<SV_PROT_D> DataFull_T;
            DataFull.push_back(DataFull_T);
            shiftUA S_T;
            Shift.push_back(S_T);
        }	
        
    }    


    

        

}packet_handler;




int main(){

    // accept signal from VSCode for pausing/stopping
    char *sudo_uid = getenv("SUDO_UID");
    if (sudo_uid) setresuid(0, 0, atoi(sudo_uid));
    printf("uid = %d\n", getuid());

    


    pthread_t draw_graphics, thread_manager;
    
    command_manager com;
    pthread_mutex_init(&(com.mutex_CM), NULL);
    pthread_mutex_init(&(com.mutex_DK), NULL);
    pthread_mutex_init(&(com.mutex_QU), NULL);
    pthread_cond_init(&com.queue_waiter, NULL);
    
    

    pthread_create(&draw_graphics, NULL, *draw, (void *) &com);
    pthread_create(&thread_manager, NULL, *manager, (void *) &com);
    pthread_join(draw_graphics, NULL);


    pthread_cond_broadcast(&com.queue_waiter);


    pthread_join(thread_manager,NULL);

    return 0;
}

void config_writer(conf_pr dev){
    std::ofstream myfile;
    myfile.open("config.txt");
    if(myfile.is_open()){
        myfile << dev.name << " = " << dev.value;



        
    myfile.close();
    }
    
}

// -------------------------------------------------------------------------------------------------------------------

void * alarm_for_prot(void * args){
    command_manager *arg = (command_manager*) args;
    int *Err = arg->Errno;
    vector<SV_PROT_NF_I> * DataKrat = arg->DataKrat;
    bool close = false;
    for(;!close;){
        sleep(1);
        for(int i = 0; i < DataKrat->size();i++){
            
            pthread_mutex_lock(&arg->mutex_DK);
            (*DataKrat)[i].cnt_str = to_string((*DataKrat)[i].smt_counter);
            if(3980<= (*DataKrat)[i].smt_counter){
                (*DataKrat)[i].signal = Green;
            }
            if(3500<= (*DataKrat)[i].smt_counter && 3980> (*DataKrat)[i].smt_counter){
                (*DataKrat)[i].signal = Yellow;
            }
            if(2000<= (*DataKrat)[i].smt_counter && 3500> (*DataKrat)[i].smt_counter){
                (*DataKrat)[i].signal = Red;
            }
            if(0 <= (*DataKrat)[i].smt_counter && 2000> (*DataKrat)[i].smt_counter){
                (*DataKrat)[i].signal = Gray;
            }
            (*DataKrat)[i].smt_counter = 0;
            pthread_mutex_unlock(&arg->mutex_DK);
            
        }
        pthread_mutex_lock(&arg->mutex_QU);
        if (arg->command_queue.front() == SV_close) {
            close = true;
        }
        pthread_mutex_unlock(&arg->mutex_QU);
        
    }  
    return 0;
}

// -------------------------------------------------------------------------------------------------------------------

void * loop_breaker(void * args){
    command_manager *arg = (command_manager*) args;
    pthread_mutex_lock(&arg->mutex_CM);
    pcap_breakloop(arg->fp);
    pthread_mutex_unlock(&arg->mutex_CM);
    return 0;
}

// -------------------------------------------------------------------------------------------------------------------

void * receive(void * args){	
    command_manager *arg = (command_manager*) args;
    int *Err = arg->Errno;

    packet_handler handler;
    
    pthread_mutex_lock(&arg->mutex_CM);       
    arg->DataKrat = &handler.DataKrat;
    arg->DataFull = &handler.DataFull;
    handler.mutex_DK = arg->mutex_DK;
    pthread_mutex_unlock(&arg->mutex_CM);

    
    Callback<void(u_char *, const struct pcap_pkthdr *, const u_char *)>::func = std::bind(&packet_handler::dispatcher_handler1, &handler, std::placeholders::_1, std::placeholders::_2,std::placeholders::_3);
    callback_t func = static_cast<callback_t>(Callback<void(u_char *, const struct pcap_pkthdr *, const u_char *)>::callback);

       
    

	pcap_loop(arg->fp,0,func,NULL);

    

    
	pcap_close(arg->fp);

     
    pthread_cond_broadcast(&arg->queue_waiter);
    

    cout<<"SV_closed \n";
    *Err = 0;
    return 0;
}

// -------------------------------------------------------------------------------------------------------------------

void * reciver_init(void * args){
    command_manager *arg = (command_manager*) args;
    int *Err = arg->Errno;

    pcap_t *fp;

     

	
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	struct bpf_program fcode;     //переменная для записи фильтра
	int res;  //переменная под ошибки 
	bpf_u_int32 mask;   /* Сетевая маска устройства */
	bpf_u_int32 net;	/* IP устройства */
    conf_pr device;
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	int inum;

    std::ifstream myfile; 
    myfile.open("./config.txt");
    if(myfile.is_open()){
        string line;
        while(getline(myfile,line)){
            line.erase(std::remove_if(line.begin(), line.end(),[](unsigned char x) { return std::isspace(x); }),
                                 line.end());
            if( line.empty() || line[0] == '#' )
            {
                continue;
            }
            auto delimiterPos = line.find("=");
            device.name = line.substr(0, delimiterPos);
            device.value = line.substr(delimiterPos + 1);



        }
    myfile.close();

    }
    else 
    {   
        std::cerr << "Couldn't open config file for reading.\n";
        pcap_if_t *alldevs;
	    pcap_if_t *dev;
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
            *Err = -1;
            pthread_exit(Err);
        }
        
        printf("Enter the interface number (1-%d):",i);
        std::cin>>(inum);
        
        if(inum < 1 || inum > i)
        {
            printf("\nInterface number out of range.\n");
            /* Free the device list */
            pcap_freealldevs(alldevs);
            *Err = -1;
            pthread_exit(Err);
        }
        
        /* Jump to the selected adapter */
        for(dev=alldevs, i=0; i< inum-1 ;dev=dev->next, i++);

        device.name = "device";
        device.value = dev->name;
        pcap_freealldevs(alldevs);
        config_writer(device);
        
    }
    
    

	/* Retrieve the device list on the local machine */
    
    /* Open the device */
    if ( (fp= pcap_open_live(device.value.c_str(),         // name of the device
                              65536,            // portion of the packet to capture. 
                              true,             // 65536 guarantees that the whole packet will be captured on all the link layers
                              1000,             // read timeout            
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", device.name.c_str());
		std::cout<<'\n'<<errbuf;
        /* Free the device list */
        
        *Err = -1;
        pthread_exit(Err);
    }

	if (pcap_datalink(fp) != DLT_EN10MB) 
		{
			fprintf(stderr, "Device %s doesn't provide Ethernet headers -not  supported\n", device.name.c_str());
			*Err = -1;
            pthread_exit(Err);
		}

	if((res = pcap_compile(fp, &fcode, "not udp and not ip and ether[12]=136 and ether[13]=186", 1, 0)) < 0) //составление фльтра 
		{	
			cout<<"\nError compiling filter: "<< res <<'\n';
			pcap_close(fp);
			*Err = -3;
        pthread_exit(Err);
		}

		//set the filter
	if((res = pcap_setfilter(fp, &fcode))<0)   //применение фильтра 
		{
			cout<<"\nError setting the filter: "<< res <<'\n';
			pcap_close(fp);
			*Err = -4;
            pthread_exit(Err);
		}

    
    printf("\nlistening on %s...\n", device.value.c_str());

    

    
    arg->fp = fp;
    return 0;
}

// -------------------------------------------------------------------------------------------------------------------

void * draw(void* args){

    command_manager *arg = (command_manager*) args;
    int *Err = arg->Errno;
    vector<SV_PROT_NF_I> * DataKrat = arg->DataKrat;
    pthread_mutex_lock(&arg->mutex_QU);

    
    
    

    //Инициализация библиотеки GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW\n";
        *Err = EXIT_FAILURE;
        pthread_exit(Err); 
    }
    //Создаю окно 

    GLFWmonitor * monitor = glfwGetPrimaryMonitor();
    const GLFWvidmode * mode = glfwGetVideoMode(monitor);

    GLFWwindow* window = glfwCreateWindow(mode->width, mode->height, "My window", monitor, NULL);
    if (!window) {
        glfwTerminate();
        *Err = -1;
        pthread_exit(Err);
    }

    glfwSetWindowMonitor(window, monitor , 0 , 0 , mode->width, mode->height,GLFW_DONT_CARE);

    // Создание контекста OpenGL
    glfwMakeContextCurrent(window);
    //Что это не знаю, но без него не работает(
    //gladLoadGL(glfwGetProcAddress);
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
    Display Display;

    Display.com = arg;
    for(int i = 0; i<4; i++){
        Display.flag[i]= false;
    }

    
    
    bool ret = LoadTextureFromFile("./image/logo2smoll.jpg", &Display.my_image_texture, &Display.my_image_width, &Display.my_image_height);
    IM_ASSERT(ret);


    

    while (!glfwWindowShouldClose(window)) { //Цикл будет выполняться пока окно не закроется
        glfwPollEvents();//Обрабатывает все события, которые происходят в окне и позволяет реагировать на них

        //Готовят imGui к отрисовке нового кадра в пользовательском интерфейсе
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        
        // Вызывает функцию
        if (!Display.flag[0] && !Display.flag[1] && !Display.flag[2] && !Display.flag[3] && Display.APP_ID==0) Display.Main_Menu();
        if (Display.flag[0] && Display.APP_ID==0) Display.Streams_SV();
        if (Display.APP_ID!=0)            Display.WindowFullInformation();
    

        


        //Завершает отрисовку интерфейса и выводит на экран результат
        ImGui::Render();

        //Очищает буфер кадра, обычно для подготовки его к отрисовке нового кадра.
        //glClear(GL_COLOR_BUFFER_BIT);

        //Рисует данные пользовательского интерфейса ImGui на текущем буфере кадра OpenGL
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        //Меняет местами буферы кадра GLFW, чтобы отобразить новый кадр на экране.
        glfwSwapBuffers(window);
    }
    
    arg->command_queue.push(Window_close);
     
    pthread_cond_broadcast(&arg->queue_waiter);
    

    pthread_mutex_unlock(&arg->mutex_QU);
    //Освобождает все выделенные ресурсы, связанные с GLFW и завершает работу этой библиотеки
    ImPlot::DestroyContext();
    glfwTerminate();
    *Err = 0;

    

    pthread_exit(Err);

    
}

// -------------------------------------------------------------------------------------------------------------------

void * manager(void* args){
    command_manager *arg = (command_manager*) args;

    pthread_t sv_receive, alarm_sv, loop_break;
    int command;
    bool program_end = false;
    bool SV_sniff_open = false;
   
    
    for(;!program_end;){
        int res = pthread_cond_wait(&arg->queue_waiter, &arg->mutex_QU);

        command = arg->command_queue.front();
        
        
        switch (command)
        {
        case SV_open:
            reciver_init((void *) arg);
            pthread_create(&sv_receive, NULL, *receive, (void *) arg);
            //pthread_create(&alarm_sv, NULL, *alarm_for_prot, (void *) arg);
            
            
            arg->command_queue.pop();
            
            SV_sniff_open = true;
            break;

        case SV_close:
            arg->sv_deinnit();
            pthread_create(&loop_break, NULL, *loop_breaker, (void *) arg);
            pthread_detach(sv_receive);
            pthread_detach(loop_break);
            
            
            
            arg->command_queue.pop();
            
            SV_sniff_open = false;
            break;
        case Window_close:

        
            arg->command_queue.pop();
            
            
            if(SV_sniff_open){
                arg->command_queue.push(SV_close);
               
            }

            arg->command_queue.push(Exit);
            


            break;
        case Exit:
            program_end = true;
            

            arg->command_queue.pop();
            *arg->Errno = 0;
  

            break;
        default:

            break;

        
        
        }
        

        

         
    }


    return 0;
}

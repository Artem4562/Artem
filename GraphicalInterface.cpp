#define GLAD_GL_IMPLEMENTATION
#define _USE_MATH_DEFINES
#include <math.h>
#include "libraries/glfw/deps/glad/gl.h"
#include <GLFW/glfw3.h>
#define GLFW_INCLUDE_NONE
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <imgui.h>
#include <implot.h>
#include <implot_internal.h>
#include <iostream>
//#include <winsock2.h>
#include <vector>
#include <hell.hpp>
#include <pcap.h>
using namespace std;


vector<char> t = {'N','G','r','i','d','_','c','a','b','l','e','_','1'};
	vector<SV_PROT_NF_I> DK = {
		SV_PROT_NF_I{{1,12,205,4,0,1},{12,239,175,48,222,46},16385,t,0},
		SV_PROT_NF_I{{2,12,205,4,0,1},{12,239,175,48,222,46},51638,t,1},
		SV_PROT_NF_I{{3,12,205,4,0,1},{12,239,175,48,222,46},13685,t,2},
		SV_PROT_NF_I{{4,12,205,4,0,1},{12,239,175,48,222,46},16385,t,3},
		SV_PROT_NF_I{{5,12,205,4,0,1},{12,239,175,48,222,46},16835,t,4},
		SV_PROT_NF_I{{6,12,205,4,0,1},{12,239,175,48,222,46},13685,t,5},
		SV_PROT_NF_I{{7,12,205,4,0,1},{12,239,175,48,222,46},16358,t,6},
		SV_PROT_NF_I{{8,12,205,4,0,1},{12,239,175,48,222,46},21635,t,7},
		SV_PROT_NF_I{{9,12,205,4,0,1},{12,239,175,48,222,46},16835,t,8},
		SV_PROT_NF_I{{10,12,205,4,0,1},{12,239,175,48,222,46},16385,t,9},
		SV_PROT_NF_I{{11,12,205,4,0,1},{12,239,175,48,222,46},16385,t,10},
		SV_PROT_NF_I{{12,12,205,4,0,1},{12,239,175,48,222,46},16385,t,11},
		SV_PROT_NF_I{{13,12,205,4,0,1},{12,239,175,48,222,46},16385,t,12},
		SV_PROT_NF_I{{14,12,205,4,0,1},{12,239,175,48,222,46},16385,t,13},
		SV_PROT_NF_I{{15,12,205,4,0,1},{12,239,175,48,222,46},16385,t,14},
        SV_PROT_NF_I{{16,12,205,4,0,1},{12,239,175,48,222,46},16385,t,15}
	};
    
SV_PROT_NF_I* a = &DK[0];

bool *flag = new bool; 
static int k=0; // для кнопок в Streams_Sv
static unsigned short f = 0; // для APP_ID в Streams_SV
static int s; // для вызова WindowFullInformation

string SVinfo(int Stream_number, char* SV_ID, unsigned short APP_ID, unsigned char MAC[6])
{   
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

    // if(ImPlot::BeginPlot("Graph U", ImVec2(300,300))){
    //     float Uax[2]={0.0, 1.0};
    //     float Uay[2]={0.0, 1.0};
    //     ImPlot::PlotLine("Ua",Uax, Uay, 2);

    //     float Ubx[2]={0.0, 1.5};
    //     float Uby[2]={0.0, 0.5};
    //     ImPlot::PlotLine("Ub",Ubx, Uby, 2);

    //     float Ucx[2]={0.0, -1.5};
    //     float Ucy[2]={0.0, -0.5};
    //     ImPlot::PlotLine("Uc",Ucx, Ucy, 2);

    //     float Unx[2]={0.0, -1.0};
    //     float Uny[2]={0.0, 1.0};
    //     ImPlot::PlotLine("Un",Unx, Uny, 2);
        
    //     ImPlot::EndPlot(); 
    // }
    
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
    ImGui::Text("%d streams detected ",int(DK.size()));
    ImGui::SetCursorPosX(0.0f);

    ImGui::SetWindowFontScale(1.5f);
    if (ImGui::Button("Return to the main menu", ImVec2(480, 50))) 
        flag[0] = false;
    ImGui::SetWindowFontScale(1.0f);
    ImGui::SetCursorPosX(0.0f);
    ImGui::SetWindowFontScale(1.5f);
   
    for( int i=6*k ; i < DK.size() && i < 6*k+6 ;i++){
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




int main() {
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
;
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

    return 0;
}
    
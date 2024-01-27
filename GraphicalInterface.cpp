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
#include <winsock2.h>
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
		SV_PROT_NF_I{{15,12,205,4,0,1},{12,239,175,48,222,46},16385,t,14}
	};
    
SV_PROT_NF_I* a = &DK[0];


bool *flag = new bool; 
const char* data[12] = {"SV_ID","APP_ID","MAC","Ua","Ub","Uc","Un","Ia","Ib","Ic","In"};
static int k=0;

const char* SVinfo(int Package_number,unsigned char* SV_ID, unsigned short APP_ID, unsigned char* MAC)
{   
    string info;
    info = "Package_number: "+ to_string(Package_number) + "\n" + "SV_ID: " + string(reinterpret_cast<char*>(SV_ID)) +"\n"+ "APP_ID: " + to_string(APP_ID) +  "\n" + "MAC: " + string(reinterpret_cast<char*>(MAC)) + "\n" ;
    return info.c_str();
};

void WindowFullInformation(int id,char* svID, bool *flag) {
    const char* Ia = "4678";
    const char* Ib = "2023";
    const char* Ic = "7698";
    const char* In = "2288";
    const char* Ua = "1520";
    const char* Ub = "1337";
    const char* Uc = "3654";
    const char* Un = "5436";
    ImGui::SetNextWindowPos(ImVec2(0, 0));    
    ImGui::SetNextWindowSize(ImVec2(480,800));
    ImGui::Begin("Protocol Data",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("SV_ID: ");
    ImGui::Text("APP_ID: ");
    ImGui::Text("MAC: ");

    ImGui::Text("Ua= %s;",Ua);
    ImGui::Text("Ub= %s;",Ub);
    ImGui::Text("Uc= %s;",Uc);
    ImGui::Text("Un= %s;",Un);

    ImGui::Text("Ia= %s;",Ia);
    ImGui::Text("Ib= %s;",Ib);
    ImGui::Text("Ic= %s;",Ic);
    ImGui::Text("In= %s;",In);

    if (ImGui::Button("Return to the list of streams")) flag[id] = false;
    // if (ImPlot::BeginPlot("Graph valid values Ia, Ib, Ic, In", SizeGraph,  ImPlotFlags_NoInputs)) {
    //     int n = 100; // количество точек на графике
    //     float* xs = new float[n];
    //     float* ys = new float[n];
    //     float step = 2 * M_PI/ n;
    //     for (int i = 0; i < n; i++) {
    //         xs[i] = i * step;
    //         ys[i] = std::sin(xs[i]);
    //     }
    //     ImPlot::PlotLine("sin(x)", xs, ys, n);

    //     delete[] xs;
    //     delete[] ys;
    //     ImPlot::EndPlot(); 
    // }
    ImGui::End();
}


void Streams_SV(bool *flag){
    ImGui::SetNextWindowPos(ImVec2(0,0));
    ImGui::SetNextWindowSize(ImVec2(480,800));
    ImGui::Begin("Streams SV",  nullptr,  ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove
    | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImVec2 sizewindow = ImGui::GetWindowSize();
    ImVec2 sizetext = ImGui::CalcTextSize("Streams SV");
    float posX = (sizewindow.x - sizetext.x) * 0.5f;
    ImGui::SetCursorPosX(posX);
    ImGui::SetWindowFontScale(1.5f);
    ImGui::Text("Streams SV ");
    ImVec2 sizetextX = ImGui::CalcTextSize("X streams detected");
    float posXX = (sizewindow.x - sizetextX.x) * 0.5f;
    ImGui::SetCursorPosX(posXX);
    ImGui::Text("X streams detected ");
    ImGui::SetCursorPosX(0.0f);

    ImGui::SetWindowFontScale(1.5f);
    if (ImGui::Button("Return to the main menu", ImVec2(480, 50))) 
        flag[0] = false;

    ImGui::SetWindowFontScale(1.0f);

    // int Package_number = 1;
    // char* SV_ID = "SV_ID";
    // char* APP_ID = "APP_ID";
    // char* MAC = "MAC";

    // int id =7;
    for(int i=0; 5*k<=i && i<5*k+4;){
        ImGui::SetCursorPosX(0.0f);
        ImGui::SetWindowFontScale(1.5f);
        if (ImGui::Button(SVinfo(i+1,&(a[i].svID)[0], a[i].AppID, a[i].Destination), ImVec2(480, 100)));
    }
    // if (5*k<id){
    //     ImGui::SetCursorPosX(0.0f);
    //     ImGui::SetWindowFontScale(1.5f);
    //     if (ImGui::Button(SVinfo(Package_number + 5*k,SV_ID, APP_ID, MAC), ImVec2(480, 100)));
    // }
    // if (5*k+1<id){
    //     ImGui::SetCursorPosX(0.0f);
    //     ImGui::SetWindowFontScale(1.5f);
    //     if (ImGui::Button(SVinfo(Package_number +5*k+1,SV_ID, APP_ID, MAC), ImVec2(480, 100)));
    // }
    // if (5*k+2<id){
    //     ImGui::SetCursorPosX(0.0f);
    //     ImGui::SetWindowFontScale(1.5f);
    //     if (ImGui::Button(SVinfo(Package_number +5*k+2,SV_ID, APP_ID, MAC), ImVec2(480, 100)));
    // }
    // if (5*k+3<id){
    //     ImGui::SetCursorPosX(0.0f);
    //     ImGui::SetWindowFontScale(1.5f);
    //     if (ImGui::Button(SVinfo(Package_number +5*k+3,SV_ID, APP_ID, MAC), ImVec2(480, 100)));
    // }
    // if (5*k+4<id){
    //     ImGui::SetCursorPosX(0.0f);
    //     ImGui::SetWindowFontScale(1.5f);
    //     if (ImGui::Button(SVinfo(Package_number +5*k+4,SV_ID, APP_ID, MAC), ImVec2(480, 100)));
    // }
    
    if (k>0){
        ImGui::SetWindowFontScale(2.5f);    
        ImGui::SetCursorPos(ImVec2(0, 630));
        if (ImGui::Button("<", ImVec2(235, 50))) k -= 1;
        ImGui::SetWindowFontScale(1.0f);
    }
    if (5*k<(sizeof(a)/sizeof(*a))-5){
        ImGui::SetWindowFontScale(2.5f);
        ImGui::SetCursorPos(ImVec2(240, 630));
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

    ImGui::End();
} 

int main() {

flag[0]=false;
flag[1]=false;
flag[2]=false;
flag[3]=false;

    FreeConsole();

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

    const char svID[8] = {'1','2','3','4','5','6','7','8'};

    // Создание контекста OpenGL
    glfwMakeContextCurrent(window);
    //Что это не знаю, но без него не работает(
    gladLoadGL(glfwGetProcAddress);
    //Частота обновления кадров в приложении такая же, как у монитора
    glfwSwapInterval(1);

    //Инициализация ImGui и Implot
    ImGui::CreateContext();
    ImPlot::CreateContext();
    //Инициализация ImGui для работы с библиотекой GLFW и OpenGL
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    //Инициализация ImGui для работы с OpenGL версии 3.3
    ImGui_ImplOpenGL3_Init("#version 130");
    //bool flag = false; // флаг окно с расширенной информацией закрыто 
    while (!glfwWindowShouldClose(window)) { //Цикл будет выполняться пока окно не закроется
        glfwPollEvents();//Обрабатывает все события, которые происходят в окне и позволяет реагировать на них

        //Готовят imGui к отрисовке нового кадра в пользовательском интерфейсе
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        
        // Вызывает функцию
        if (!flag[0] && !flag[1] && !flag[2] && !flag[3]) Main_Menu(flag);
        if (flag[0]) Streams_SV(flag);


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
    
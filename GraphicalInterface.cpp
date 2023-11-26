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

bool *flag = new bool; // флаг окно с расширенной информацией закрыто 


void WindowFullInformation(int id,char* svID, bool *flag) {
    const char* PackageName = "C++";
    const char* MACdst = "01:0c:cd:01:00:10";
    const char* Ia = "4678";
    const char* Ib = "2023";
    const char* Ic = "7698";
    const char* In = "2288";
    const char* Ua = "1520";
    const char* Ub = "1337";
    const char* Uc = "3654";
    const char* Un = "5436";
    ImGui::SetNextWindowPos(ImVec2(0, 0));    
    ImGui::SetNextWindowSize(ImVec2(800,400));
    ImGui::Begin("Protocol Data",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("svID: %s; Package Name: %s; MAC dst: %s;  ", svID, PackageName, MACdst);
    ImGui::Text("Ia= %s;  Ua= %s;",Ia,Ua);
    ImGui::Text("Ib= %s;  Ub= %s;",Ib,Ub);
    ImGui::Text("Ic= %s;  Uc= %s;",Ic,Uc);
    ImGui::Text("In= %s;  Un= %s;",In,Un);
    if (ImGui::Button("Close")) flag[id] = false;

    
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

void Monitor(int id,char svID,int a, int b ,bool *flag){
    const char* Stream = "Potok";
    const char* MACdst = "01:0c:cd:01:00:10";
    // const char* svID = "0000MU0001";
    ImGui::SetNextWindowPos(ImVec2(a, b)); // Указывает конкретную область, в которой должно появиться окно
    ImGui::SetNextWindowSize(ImVec2(400,165));
    ImGui::Begin(&svID,  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("svID: %s; Stream: %s;  MAC dst: %s; ", &svID, Stream, MACdst);

    if (ImGui::Button("Open")) flag[id] = true;
    // if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && ImGui::IsWindowHovered()) {
    //     flag = true;
    // }
    if(flag[id]){
        WindowFullInformation(id,&svID, flag);
    }
    ImGui::End();   
} 

void Common_Window(bool *flag){
    ImGui::SetNextWindowPos(ImVec2(0,0));
    ImGui::SetNextWindowSize(ImVec2(400,800));
    ImGui::Begin("Streams SV",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::SetCursorPosX(200.0f);
    ImGui::Text("X streams detected");
    ImGui::SetCursorPosX(0.0f);
    // if (ImGui::Button("Main Menu", ImVec2(150, 50))) flag[id] = false;
    // while (){
    //     Monitor(0,'1',0, 0,flag);
    // }

}

void Main_Menu(bool *flag){
    ImGui::SetNextWindowPos(ImVec2(0,0)); // Указывает конкретную область, в которой должно появиться окно
    ImGui::SetNextWindowSize(ImVec2(400,800));
    ImGui::Begin(" ",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove| ImGuiWindowFlags_NoInputs);
    ImVec2 sizewindow = ImGui::GetWindowSize();
    ImVec2 sizetext = ImGui::CalcTextSize("Main Menu");
    float posX = (sizewindow.x - sizetext.x) * 0.5f;
    ImGui::SetCursorPosX(posX);
    ImGui::Text("Main Menu"); 
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(0,45));
    ImGui::SetNextWindowSize(ImVec2(200,200));
    ImGui::Begin("Streams SV",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    if (ImGui::Button("Streams SV", ImVec2(150, 50))) ;
    // if(flag[id]){
    //     Common_Window();
    // }
    ImGui::End(); 

    ImGui::SetNextWindowPos(ImVec2(200,45));
    ImGui::SetNextWindowSize(ImVec2(200,200));
    ImGui::Begin("Streams GOOSE ",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    if (ImGui::Button("Streams GOOSE", ImVec2(150, 50))) ;
    ImGui::End();  
    
    ImGui::SetNextWindowPos(ImVec2(0,245));
    ImGui::SetNextWindowSize(ImVec2(200,200));
    ImGui::Begin("Generator SV ",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    if (ImGui::Button("Generator SV", ImVec2(150, 50))) ;
    ImGui::End();
    
    ImGui::SetNextWindowPos(ImVec2(200,245));
    ImGui::SetNextWindowSize(ImVec2(200,200));
    ImGui::Begin(" Generator GOOSE",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    if (ImGui::Button("Generator GOOSE", ImVec2(150, 50))) ;
    ImGui::End();
    
    // if(flag[id]){
    //     WindowFullInformation(id,&svID, flag);
    // }
       
    
} 

int main(int, char**) {
    FreeConsole();
    flag[0]=0;
    flag[1]=0;
    flag[2]=0;
    flag[3]=0;
    flag[4]=0;
    flag[5]=0;
    //Инициализация библиотеки GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW\n";
        return EXIT_FAILURE;
    }
    //Создаю окно 
    GLFWwindow* window = glfwCreateWindow(400, 800, "My window", NULL, NULL);
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
        // WindowFullInformation(&IAMY,&TIMEX);
        // Main_Menu();
        
        Monitor(0,'1',0, 0,flag);
        // Monitor(1,'2',400, 0,flag);
        // Monitor(2,'3',0, 200,flag);
        // Monitor(3,'4',400, 200,flag);
        // Monitor(4,'5',0, 400,flag);
        // Monitor(5,'6',400, 400,flag);

        // Monitor();

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
    
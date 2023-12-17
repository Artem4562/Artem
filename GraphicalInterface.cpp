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
const char* data[12] = {"SV_ID","APP_ID","MAC","Ua","Ub","Uc","Un","Ia","Ib","Ic","In"};



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
    ImGui::Begin("Streams SV",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove| ImGuiWindowFlags_NoInputs);
    ImVec2 sizewindow = ImGui::GetWindowSize();
    ImVec2 sizetext = ImGui::CalcTextSize("X streams detected");
    float posX = (sizewindow.x - sizetext.x) * 0.5f;
    ImGui::SetCursorPosX(posX);
    ImGui::SetWindowFontScale(1.5f);
    ImGui::Text("X streams detected ");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::SetCursorPosX(0.0f);
    if (ImGui::Button("Return to the main menu", ImVec2(200, 50))) flag[0] = false;
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(0,130));
    ImGui::SetNextWindowSize(ImVec2(480,200));
    ImGui::Begin("Package number: ",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("hfdshjfhsdhfjsdhjfhjsdhjfds");
    ImGui::End();
    // // ImGui::Text("SV_ID: %s",data[0]);
    // // ImGui::Text("APP_ID: %s",data[1]);
    // // ImGui::Text("MAC: %s", data[2]);

    // // int i =1;
    // // while (flag[0]){
    // //     ImGui::Begin(" ",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove)
    // //     ImGui::Text("Package number: %d", i);
    // //     ImGui::Text("SV_ID: %s", data[0]);
    // //     ImGui::Text("APP_ID: %s", data[1]);
    // //     ImGui::Text("MAC: %s", data[2]);
    // //     if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(0)) 
    // //         flag[id] = true;
    // //     if (flag[id])  
    // //         WindowFullInformation(int id,char* svID, bool *flag);
    // //     ImGui::End();
    // //     i+=1;
    // // }

    // ImGui::End();
}

void Main_Menu(bool *flag){
    ImGui::SetNextWindowPos(ImVec2(0,0)); // Указывает конкретную область, в которой должно появиться окно
    ImGui::SetNextWindowSize(ImVec2(480,800));
    ImGui::Begin(" ",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImVec2 sizewindow = ImGui::GetWindowSize();
    ImVec2 sizetext = ImGui::CalcTextSize("Main Menu");
    float posX = (sizewindow.x - sizetext.x) * 0.5f;
    ImGui::SetCursorPosX(posX);

    ImGui::SetWindowFontScale(1.5f);
    ImGui::Text("Main Menu");
    if (ImGui::Button("Streams SV", ImVec2(480, 100))) flag[0] = true;
    if (flag[0]) Streams_SV(flag);
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

// data[0]= "SV_ID";
// data[1]= "APP_ID";
// data[2]= "MAC";
// data[3]= "Ua";
// data[4]= "Ub";
// data[5]= "Uc";
// data[6]= "Un";
// data[7]= "Ia";
// data[8]= "Ib";
// data[9]= "Ic";
// data[10]= "In";
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
        // WindowFullInformation(&IAMY,&TIMEX);
        Main_Menu(flag);
        // Monitor(0,'1',0, 0,flag);

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
    
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
#include <Windows.h>


void DrawVectorDiagram(){
    ImGui::SetNextWindowSize(ImVec2(800,400));
    ImGui::Begin("Monitor");
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - ImGui::CalcTextSize("Справа выровненный текст").x);
    ImGui::Text("Справа выровненный текст");

    ImGui::SetCursorPosX(0);
    ImGui::Text("Слева выровненный текст");
    ImGui::End();
} 

void WindowFullInformation() {
    ImVec2 SizeGraph (800,300);
    const char* PackageName = "C++";
    const char* Stream = "Potok";
    const char* MACdst = "01:0c:cd:01:00:10";
    const char* MACsrc = "00:50:c2:4f:94:3b";
    const char* svID = "0000MU0001";
    const char* Skippackets = "tut chto-to napisano";    
    ImGui::SetNextWindowSize(ImVec2(800,400));
    ImGui::Begin("Protocol data",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("Package Name: %s;  Stream: %s;  MAC dst: %s;  MAC src: %s;", PackageName, Stream, MACdst, MACsrc );
    ImGui::Text("svID: %s;  Skipped package: %s;",svID, Skippackets);

    if (ImPlot::BeginPlot("Graph Ia, Ib, Ic, In", SizeGraph, ImPlotFlags_NoInputs)) {
        int n = 100; // количество точек на графике
        float* xs = new float[n];
        float* ys = new float[n];
        float step = 2 * M_PI/ n;
        for (int i = 0; i < n; i++) {
            xs[i] = i * step;
            ys[i] = std::sin(xs[i]);
        }
        ImPlot::PlotLine("sin(x)", xs, ys, n);

        delete[] xs;
        delete[] ys;
        ImPlot::EndPlot();
    }
    
    if (ImPlot::BeginPlot("Graph Ua, Ub, Uc, Un", SizeGraph,  ImPlotFlags_NoInputs)) {
        int n = 100; // количество точек на графике
        float* xs = new float[n];
        float* ys = new float[n];
        float step = 2 * M_PI/ n;
        for (int i = 0; i < n; i++) {
            xs[i] = i * step;
            ys[i] = std::sin(xs[i]);
        }
        ImPlot::PlotLine("sin(x)", xs, ys, n);

        delete[] xs;
        delete[] ys;
        ImPlot::EndPlot();
    }
    
    if (ImPlot::BeginPlot("Graph valid values Ua, Ub, Uc, Un", SizeGraph,  ImPlotFlags_NoInputs)) {
        int n = 100; // количество точек на графике
        float* xs = new float[n];
        float* ys = new float[n];
        float step = 2 * M_PI/ n;
        for (int i = 0; i < n; i++) {
            xs[i] = i * step;
            ys[i] = std::sin(xs[i]);
        }
        ImPlot::PlotLine("sin(x)", xs, ys, n);

        delete[] xs;
        delete[] ys;
        ImPlot::EndPlot(); 
    }
    
    if (ImPlot::BeginPlot("Graph valid values Ia, Ib, Ic, In", SizeGraph,  ImPlotFlags_NoInputs)) {
        int n = 100; // количество точек на графике
        float* xs = new float[n];
        float* ys = new float[n];
        float step = 2 * M_PI/ n;
        for (int i = 0; i < n; i++) {
            xs[i] = i * step;
            ys[i] = std::sin(xs[i]);
        }
        ImPlot::PlotLine("sin(x)", xs, ys, n);

        delete[] xs;
        delete[] ys;
        ImPlot::EndPlot(); 
    }
    

    ImGui::End();
}

void Monitor() {
    const char* Stream = "Potok";
    const char* MACdst = "01:0c:cd:01:00:10";
    const char* MACsrc = "00:50:c2:4f:94:3b";
    const char* svID = "0000MU0001";
    const char* Ia = "4678";
    const char* Ib = "2023";
    const char* Ic = "7698";
    const char* In = "2288";
    const char* Ua = "1520";
    const char* Ub = "1337";
    const char* Uc = "3654";
    const char* Un = "5436";
    ImGui::SetNextWindowSize(ImVec2(400,140));
    ImGui::Begin("Monitor",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("Stream: %s;  MAC dst: %s; ", Stream, MACdst);
    ImGui::Text("MAC src: %s;  svID: %s;", MACsrc,svID);
    ImGui::Text("Ia= %s;  Ua= %s;",Ia,Ua);
    ImGui::Text("Ib= %s;  Ub= %s;",Ib,Ub);
    ImGui::Text("Ic= %s;  Uc= %s;",Ic,Uc);
    ImGui::Text("In= %s;  Un= %s;",In,Un);
    ImGui::End();
}

int main(int, char**) {
    FreeConsole();
    //Инициализация библиотеки GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW\n";
        return EXIT_FAILURE;
    }
    //Создаю окно 
    GLFWwindow* window = glfwCreateWindow(800, 400, "My window", NULL, NULL);
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
        // WindowFullInformation();
        // DrawVectorDiagram();
        Monitor();

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
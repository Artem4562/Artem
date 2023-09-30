#define GLAD_GL_IMPLEMENTATION
#define _USE_MATH_DEFINES
#include <math.h>
#include "external/glfw/deps/glad/gl.h"
#include "implot.h"
#include "implot_internal.h"
#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <iostream>


void DrawVectorDiagram(){

    ImGui::Begin("Protocol data");
        if (ImPlot::BeginPlot("Graph Ia, Ib, Ic, In", ImVec2(1300,200))) {
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
        }
        ImPlot::EndPlot();
    ImGui::End();
} 

void WindowBriefInformation(ImVec2 customWindowSize, GLFWwindow* window) {
    const char* PackageName = "C++";
    const char* Stream = "Potok";
    const char* MACdst = "01:0c:cd:01:00:10";
    const char* MACsrc = "00:50:c2:4f:94:3b";
    const char* svID = "0000MU0001";
    const char* Skippackets = "tut chto-to napisano";    
    ImGui::SetWindowSize(customWindowSize);
    ImGui::Begin("Protocol data",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("Package Name: %s;  Stream: %s;  MAC dst: %s;  MAC src: %s;  svID: %s;  Number of packets to skip: %s;", PackageName, Stream, MACdst, MACsrc, svID, Skippackets );
    
    if (ImPlot::BeginPlot("Graph Ia, Ib, Ic, In", ImVec2(1300,200), ImPlotFlags_NoInputs)) {
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
    }
    ImPlot::EndPlot();
    if (ImPlot::BeginPlot("Graph Ua, Ub, Uc, Un", ImVec2(1300,200),  ImPlotFlags_NoInputs)) {
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
    }
    ImPlot::EndPlot();
    if (ImPlot::BeginPlot("Graph valid values Ua, Ub, Uc, Un", ImVec2(1300,200),  ImPlotFlags_NoInputs)) {
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
    }
    ImPlot::EndPlot(); 
    if (ImPlot::BeginPlot("Graph valid values Ia, Ib, Ic, In", ImVec2(1300,200),  ImPlotFlags_NoInputs)) {
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
    }
    ImPlot::EndPlot(); 

    ImGui::End();
}

int main(int, char**) {
    //Инициализация библиотеки GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW\n";
        return EXIT_FAILURE;
    }
    //Создаю окно 
    GLFWwindow* window = glfwCreateWindow(1920, 1080, "My window", NULL, NULL);
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
        
        ImVec2 customWindowSize(1920, 1080);
        // Вызывает функцию
        WindowBriefInformation(customWindowSize,window);

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
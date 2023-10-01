#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <iostream>
#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#define GLAD_GL_IMPLEMENTATION
#include "libraries/glfw/deps/glad/gl.h"
#include <implot.h>
#include <implot_internal.h>

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
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    //Инициализация ImGui для работы с OpenGL версии 3.3
    ImGui_ImplOpenGL3_Init("#version 130");

    while (!glfwWindowShouldClose(window)) { //Цикл будет выполняться пока окно не закроется
        glfwPollEvents();//Обрабатывает все события, которые происходят в окне и позволяет реагировать на них

        //Готовят imGui к отрисовке нового кадра в пользовательском интерфейсе
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("Protocol data");
        DrawVectorDiagram();
        ImGui::End();

        ImGui::Render();


        //Очищает буфер кадра, обычно для подготовки его к отрисовке нового кадра.
        glClear(GL_COLOR_BUFFER_BIT);

        //Рисует данные пользовательского интерфейса ImGui на текущем буфере кадра OpenGL
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        //Меняет местами буферы кадра GLFW, чтобы отобразить новый кадр на экране.
        glfwSwapBuffers(window);
    }
    glfwTerminate();
    

    return 0;
}
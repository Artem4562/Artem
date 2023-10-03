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
#include <thread>
#include <mutex>

// при подключении многопотока убрать
#include<algorithm>


void DrawVectorDiagram(){
    ImGui::SetNextWindowSize(ImVec2(800,400));
    ImGui::Begin("Monitor");
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - ImGui::CalcTextSize("Справа выровненный текст").x);
    ImGui::Text("Справа выровненный текст");

    ImGui::SetCursorPosX(0);
    ImGui::Text("Слева выровненный текст");
    ImGui::End();
} 

void WindowFullInformation(std::vector<float> *Iay,std::vector<float> *Time) {
    ImVec2 SizeGraph (800,300);
    const char* PackageName = "C++";
    const char* Stream = "Potok";
    const char* MACdst = "01:0c:cd:01:00:10";
    const char* MACsrc = "00:50:c2:4f:94:3b";
    const char* svID = "0000MU0001";
    const char* Skippackets = "tut chto-to napisano";    
    ImGui::SetNextWindowSize(ImVec2(800,600));
    ImGui::Begin("Protocol data",  nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove);
    ImGui::Text("Package Name: %s;  Stream: %s;  MAC dst: %s;  MAC src: %s;", PackageName, Stream, MACdst, MACsrc );
    ImGui::Text("svID: %s;  Skipped package: %s;",svID, Skippackets);

    if (ImPlot::BeginPlot("Graph Ia, Ib, Ic, In", SizeGraph, NULL)) {
        int n = (*Iay).size(); // количество точек на графике
        int k=0;
        if(n>200) k=n-200;
        float *xs = &((*Time)[k]);
        float *ys = &((*Iay)[k]);
        //float* xs = new float[n];
        //float* ys = new float[n];
        // float step = 2 * M_PI/ n;
        // for (int i = 0; i < n; i++) {
        //     xs[i] = i * step;
        //     ys[i] = std::sin(xs[i]);
        // }
        ImPlot::PlotLine("sin(x)", xs, ys, 200);

        //delete[] xs;
        //delete[] ys;
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
    //FreeConsole();
    
    int k = 1000;
    std::vector<float> Y ({-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074,1053,1025,991,951,905,854,797,736,670,599,525,448,368,286,202,117,31,-55,-141,-226,-309,-391,-470,-547,-619,-689,-753,-814,-869,-919,-963,-1001,-1033,-1059,-1078,-1091,-1097,-1096,-1088,-1074,-1052,-1025,-991,-951,-905,-854,-797,-736,-670,-599,-525,-448,-368,-286,-202,-117,-31,55,141,226,309,391,470,547,620,689,754,814,869,919,963,1001,1033,1059,1078,1091,1097,1096,1088,1074});
    std::vector<float> X ({99,347,596,846,1114,1517,1704,1903,2172,2362,2599,2979,3170,3388,3596,4035,4224,4412,4599,4846,5105,5346,5597,5846,6096,6483,6672,6861,7103,7346,7597,7845,8098,8389,8620,8846,9282,9470,9657,9843,10095,10345,10597,10849,11103,12277,12277,12277,12278,15361,15361,15361,15361,15361,15361,15362,15362,15362,15362,15375,15375,15376,15598,15917,16212,16629,16629,16941,17402,17402,17637,17945,18233,18492,18759,19058,19508,19508,19721,19934,20155,21047,21047,21047,25116,25116,25117,25117,25117,25117,25117,25117,25467,25468,25468,25468,25468,25468,25469,25469,25469,25476,25711,26016,26300,26581,26806,27208,27208,27461,27692,27911,28157,28529,28752,28967,29283,29577,29778,29975,30388,30389,30716,30962,31297,31674,31675,31954,32165,32437,32653,32870,33193,33523,33776,33992,34291,34615,34615,34996,35411,35412,35739,35951,36179,36505,36764,37094,37424,37425,37763,38057,38363,38363,38819,39149,39149,39482,39696,39929,40147,40365,40605,40858,41096,41470,41656,41842,42094,42345,42689,42923,43127,43500,43687,43873,44095,44345,44611,44844,45107,45348,45595,45845,46095,46345,46605,46845,47103,47345,47595,47845,48095,48367,48595,48869,49106,49346,49595,49845,50094,50345,50596,50881,51108,51481,51667,51853,52095,52345,52595,52845,53102,53349,53595,53845,54094,54351,54595,54844,55102,55346,55595,55974,56160,56346,56594,56847,57103,57352,57595,57845,58094,58345,58594,58845,59103,59344,59594,59844,60094,60344,60595,60844,61098,61471,61657,61844,62095,62345,62594,62845,63102,63475,63661,63849,64094,64345,64594,64847,65103,65345,65595,65847,66095,66344,66595,66844,67104,67344,67594,67844,68116,68345,68595,68844,69102,69345,69595,69844,70095,70470,70656,70843,71103,71478,71731,71942,72132,72344,72594,72883,73126,73345,73594,73845,74103,74344,74594,74844,75102,75344,75595,75844,76094,76361,76594,76844,77108,77360,77610,77844,78498,78498,78709,78896,79102,80650,80651,80651,80651,80652,80652,84549,84550,84551,84552,84552,84552,84552,84552,84594,84594,84595,84595,84595,84596,84596,84596,84911,85138,85361,85678,85929,86152,86435,86658,86909,87185,87439,87667,87885,88094,88367,88640,88848,89102,89361,89618,89844,90094,90345,90610,90845,91102,91476,91663,91859,92118,92374,92593,92844,93102,93347,93594,93861,94121,94342,94600,94850,95122,95351,95597,95847,96098,96349,96595,96894,97118,97405,97628,97907,98258,98482,98702,98893,99101,100300,100300,100301,100301,101460,101460,101460,101461,101462,103515,103515,103515,103516,103516,103516,103516,103517,103754,103987,104221,104453,104768,105050,105281,105512,105753,106036,106298,106538,106802,107038,107271,107505,107750,107992,108208,108702,108702,108970,109252,109522,109727,110011,110287,110513,110754,110972,111231,111655,111657,111883,112106,112384,112594,112847,113102,113343,113593,113843,114093,114404,114592,114844,115104,115346,115602,115859,116120,116352,116728,116946,117134,117345,117592,117844,118094,118344,118622,118844,119103,119344,119594,119843,120094,120343,120594,120915,121127,121343,121594,121843,122094,122344,122676,122866,123101,123475,123661,123847,124093,124343,124593,124843,125101,125343,125593,125843,126094,126343,126593,126844,127101,127343,127593,127843,128093,128343,128594,128843,129101,129346,129593,129843,130093,130344,130594,130843,131100,131482,131670,131857,132096,132345,132599,132847,133101,133343,133593,133843,134092,134343,134593,134943,135163,135349,135594,135859,136109,136348,136593,136843,137101,137359,137593,137842,138093,138344,138593,138844,139101,139343,139592,139843,140093,140359,140593,140843,141093,141466,141652,141838,142093,142358,142593,142853,143101,143343,143715,143901,144088,144343,144725,144911,145097,145493,145679,145865,146092,146343,146593,146843,147313,147516,147710,147904,148096,148347,148596,148847,149124,149343,149592,149843,150111,150343,150592,150914,151122,151495,151681,151867,152092,152342,152593,152842,153100,153342,153592,153844,154107,154342,154833,155062,155249,155435,155621,156021,156208,156394,156599,156843,157101,157342,157592,157843,158092,158342,158592,158845,159121,159389,159764,159968,160154,160359,160592,160843,161095,161476,161662,161848,162092,162343,162593,162863,163100,163473,163659,163854,164092,164343,164593,164886,165108,165344,165592,165858,166092,166342,166592,166860,167100,167342,167592,167867,168092,168342,168592,168842,169100,169341,169592,169843,170092,170343,170592,170858,171100,171473,171659,171845,172092,172342,172592,172843,173100,173342,173592,173863,174106,174752,174752,174949,175164,175385,175593,175842,176092,176342,176592,176843,177100,177342,177592,177843,178093,178342,178592,178842,179100,179342,179592,179842,180093,180342,180639,180845,181094,181477,181713,181900,182088,182348,182593,182847,183100,183473,183659,183845,184092,184342,184606,184842,185100,185342,185592,185842,186092,186342,186592,186842,187100,187342,187594,187842,188092,188342,188591,188843,189099,189341,189592,189842,190092,190343,190592,190964,191210,191396,191610,191842,192091,192342,192592,192842,193100,193342,193624,193841,194092,194337,194592,194842,195099,195341,195592,195842,196092,196342,196591,197168,197169,197378,197606,197842,198092,198344,198607,198860,199103,199344,199616,199838,200106,200341,200592,200842,201100,201489,201675,201861,202109,202371,202591,202841,203099,203471,203659,203845,204092,204342,204592,204874,205119,205557,205636,206017,206213,206408,206618,206848,207103,207342,207613,207841,208093,208342,208606,208842,209169,209410,209648,209884,210130,210373,210611,210849,211146,211386,211620,211897,212145,212489});
    std::transform(X.begin(), X.end(), X.begin(), [k](float &c){ return c/k; });
    
    std::mutex window_mutex;
    std::vector<float> IAMY((200,0));
    std::vector<float> TIMEX((200,0));
    bool window_flag=true;

    std::thread t1([&](){
        //Инициализация библиотеки GLFW
        if (!glfwInit()) {
            std::cerr << "Failed to initialize GLFW\n";
            return EXIT_FAILURE;
        }
        //Создаю окно 
        GLFWwindow* window = glfwCreateWindow(1920, 1080, "My window", NULL, NULL);
        if (!window) {
            glfwTerminate();
            window_mutex.lock();
            window_flag=false;
            window_mutex.unlock();
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
            WindowFullInformation(&IAMY,&TIMEX);
            // DrawVectorDiagram();
            //Monitor();

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
        window_mutex.lock();
        window_flag=false;
        window_mutex.unlock();
        return 0;
    });

    std::thread t2 ([&](){
        int i;
        i=0;
        while(window_flag){
            if(i>=852) i=0;
            IAMY.push_back(Y[i]);
            TIMEX.push_back(X[i]);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            k++;
            if(IAMY.size()>400 || TIMEX.size()>400){
                auto begin1 = IAMY.cbegin(); 
                auto end1   = IAMY.cend();
                auto begin2 = TIMEX.cbegin(); 
                auto end2   = TIMEX.cend();
                IAMY.erase(begin1 , end1 - 201);
                TIMEX.erase(begin2 , end2 - 201);
            }
            i++;
            std::cout<<window_flag<<'\n';
        }
        return 0;
    });

    t1.join();
    t2.join();
    
}
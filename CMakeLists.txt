cmake_minimum_required(VERSION 3.22)
project(oke VERSION 0.9.1 LANGUAGES C CXX)
include(CTest)
set (CMAKE_CXX_STANDARD 17)





add_executable(Testbigfile Testbigfile.cpp )
target_link_libraries(Testbigfile pcap)
target_link_libraries(Testbigfile parsestream)


add_test(NAME Testbigfile
         COMMAND Testbigfile.exe)

         


add_executable(gui 
        lol.cpp
)

add_executable(graph GraphicalInterface.cpp)
target_link_libraries(graph PRIVATE parsestream)
target_link_libraries(graph PRIVATE imgui)
target_link_libraries(graph PRIVATE implot)
target_link_libraries(graph PRIVATE glfw)

add_subdirectory(libraries/glfw)
add_subdirectory(libraries/imgui-w)
add_subdirectory(libraries/implot-w/)
add_subdirectory(libraries/parse_stream)

target_link_libraries(gui PRIVATE imgui)
target_link_libraries(gui PRIVATE implot)
target_link_libraries(gui PRIVATE glfw)
target_link_libraries(gui PRIVATE parsestream)



add_executable(potok onvpotoke.cpp)

add_executable(pthrtest pthreadtest.cpp)


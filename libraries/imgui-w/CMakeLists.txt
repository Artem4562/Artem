cmake_minimum_required(VERSION 3.10)
project(imgui)

add_library(${PROJECT_NAME} 
    imgui/imgui.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_widgets.cpp
    imgui/imgui_demo.cpp
    imgui/backends/imgui_impl_glfw.cpp
    imgui/backends/imgui_impl_opengl3.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC imgui imgui/backends)
target_link_libraries(${PROJECT_NAME} PUBLIC glfw)
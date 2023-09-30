cmake_minimum_required(VERSION 3.27)
project(oke VERSION 0.9.1)
include(CTest)



add_executable(Testmisc Testmisc.cpp )
add_subdirectory(libraries)


add_executable(Testbigfile Testbigfile.cpp )
target_include_directories(Testbigfile PUBLIC "./npcap-sdk/Include") 
target_link_directories(Testbigfile PUBLIC "./npcap-sdk/Lib/x64")
target_link_libraries(Testbigfile wpcap.lib)
target_link_libraries(Testbigfile parsestream)

add_test(NAME Testbigfile
         COMMAND Testbigfile.exe)

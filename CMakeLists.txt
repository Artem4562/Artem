cmake_minimum_required(VERSION 3.27)
project(oke VERSION 0.9.1)
include(CTest)



add_executable(lol main.cpp )
add_subdirectory(libraries)


add_executable(exefile1 readerfile.cpp )
target_include_directories(exefile1 PUBLIC "./npcap-sdk/Include") 
target_link_directories(exefile1 PUBLIC "./npcap-sdk/Lib/x64")
target_link_libraries(exefile1 wpcap.lib)
target_link_libraries(exefile1 parsestream)

add_test(NAME TestInstantiator
         COMMAND exefile1.exe)

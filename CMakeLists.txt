cmake_minimum_required(VERSION 3.27)
project(oke)
set(CMAKE_BUILD_TYPE Debug)

add_executable(${PROJECT_NAME} network_interface.cpp )
target_include_directories(${PROJECT_NAME} PUBLIC "./npcap-sdk/Include") 
target_link_directories(${PROJECT_NAME} PUBLIC "./npcap-sdk/Lib")
target_link_libraries(${PROJECT_NAME} wpcap.lib)


add_executable(reader Sample.cpp )
target_include_directories(reader PUBLIC "./npcap-sdk/Include") 
target_link_directories(reader PUBLIC "./npcap-sdk/Lib")
target_link_libraries(reader wpcap.lib)



#Sample.cpp network_interface.cpp
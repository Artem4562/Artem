cmake_minimum_required(VERSION 3.27)
project(oke VERSION 0.9.1)


add_executable(${PROJECT_NAME} network_interface.cpp )
target_include_directories(${PROJECT_NAME} PUBLIC "./npcap-sdk/Include") 
target_link_directories(${PROJECT_NAME} PUBLIC "./npcap-sdk/Lib/x64")
target_link_libraries(${PROJECT_NAME} wpcap.lib)


add_executable(reader Sample.cpp )
target_include_directories(reader PUBLIC "./npcap-sdk/Include") 
target_link_directories(reader PUBLIC "./npcap-sdk/Lib/x64")
target_link_libraries(reader wpcap.lib)

add_executable(network New_York.cpp )
target_include_directories(network PUBLIC "./npcap-sdk/Include") 
target_link_directories(network PUBLIC "./npcap-sdk/Lib/x64")
target_link_libraries(network wpcap.lib)


add_executable(lol main.cpp )
add_subdirectory(libraries)


add_executable(exefile1 readerfile.cpp )
target_include_directories(exefile1 PUBLIC "./npcap-sdk/Include") 
target_link_directories(exefile1 PUBLIC "./npcap-sdk/Lib/x64")
target_link_libraries(exefile1 wpcap.lib)
target_link_libraries(exefile1 parsestream)



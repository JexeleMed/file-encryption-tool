cmake_minimum_required(VERSION 3.29)
project(password_manager)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)



add_executable(password_manager
        main.cpp
        AES.h
        AES.cpp)

add_custom_command(
        TARGET password_manager POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_SOURCE_DIR}/sample.txt"
        "$<TARGET_FILE_DIR:password_manager>/sample.txt"
)

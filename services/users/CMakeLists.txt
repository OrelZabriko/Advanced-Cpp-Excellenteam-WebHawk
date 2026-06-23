cmake_minimum_required(VERSION 3.16)
project(users_service)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon REQUIRED)

add_executable(${PROJECT_NAME} main.cc controllers/AuthController.cc)
target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon cryptopp)
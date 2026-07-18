cmake_minimum_required(VERSION 3.16)
project(backend_registry)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Drogon REQUIRED)

add_executable(${PROJECT_NAME}
    main.cc
    controllers/BackendController.cc
    services/BackendService.cc
    repositories/BackendRepository.cc
    utils/ApiKeyGenerator.cc
    ../../shared/DB_Repository.cc
)

target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon)
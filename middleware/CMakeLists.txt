cmake_minimum_required(VERSION 3.16)
project(middleware)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Drogon REQUIRED)

# No shared/DB_Repository.cc here - unlike the other three services, the
# middleware never talks to Postgres directly; it only calls users,
# security-engine, and backend-registry over HTTP (see services/ProxyService.cc).
add_executable(${PROJECT_NAME}
    main.cc
    services/ProxyService.cc
)

target_link_libraries(${PROJECT_NAME} PRIVATE Drogon::Drogon)
cmake_minimum_required(VERSION 3.22.1)
project(sa_engine)

add_library(sa_engine SHARED sa_engine.cpp)

find_library(log-lib log)

target_link_libraries(sa_engine ${log-lib})

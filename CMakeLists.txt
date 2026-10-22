cmake_minimum_required(VERSION 3.11)
project(HEVD_EXP LANGUAGES CXX)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_INCLUDE
    include/exp/stackoverflow.hpp
    include/exp/exploit.hpp
    include/exp/arbitraryWrite.hpp
    include/exp/uaf.hpp

    include/common/shellcode.hpp
    include/common/memtools.hpp
    include/common/gadget.hpp
)
set(PROJECT_SOURCE
    src/main.cpp

    src/exp/stackoverflow.cpp
    src/exp/exploit.cpp
    src/exp/arbitraryWrite.cpp
    src/exp/uaf.cpp

    src/common/shellcode.cpp
    src/common/memtools.cpp
    src/common/gadget.cpp
)

# Specify MSVC UTF-8 encoding
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

add_executable(${PROJECT_NAME} ${PROJECT_INCLUDE} ${PROJECT_SOURCE})
target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)
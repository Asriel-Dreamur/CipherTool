cmake_minimum_required(VERSION 3.10)
project(CipherTool LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(CipherToolGUI
    src/ui/gui_win32.cpp
    src/core/cipher_step.cpp
    src/core/cipher_scheme.cpp
    src/core/cipher_engine.cpp
    src/core/utils.cpp
)
target_include_directories(CipherToolGUI PRIVATE src/core)
target_link_libraries(CipherToolGUI comctl32)
set_target_properties(CipherToolGUI PROPERTIES WIN32_EXECUTABLE TRUE)
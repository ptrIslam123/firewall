cmake_minimum_required(VERSION 3.10)
project(firewall)

# Устанавливаем стандарт C
set(CMAKE_C_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Включаем оптимизации и SIMD инструкции
add_compile_options(-O3 -march=native -msse4.2 -mssse3)

# Ищем DPDK
find_package(PkgConfig REQUIRED)
pkg_check_modules(RTE_LIB libdpdk REQUIRED)

# Добавляем исполняемый файл
add_executable(firewall main.cpp)

# Подключаем библиотеки DPDK
target_link_libraries(firewall
    ${RTE_LIB_LIBRARIES}
    pthread
    dl
    numa
    rt
)

target_include_directories(firewall PRIVATE
    ${RTE_LIB_INCLUDE_DIRS}
)

target_compile_options(firewall PRIVATE
    ${RTE_LIB_CFLAGS}
    -O3
    -g
    -march=native
    -msse4.2
    -mssse3
    -DALLOW_EXPERIMENTAL_API
)

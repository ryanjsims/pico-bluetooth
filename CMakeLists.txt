cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

include(lib/pico-sdk/pico_sdk_init.cmake)

project(pico-bluetooth)

pico_sdk_init()

# add_subdirectory(lib/pico-web-client)
# target_compile_definitions(pico_web_client PRIVATE "LOG_LEVEL=$ENV{LOG_LEVEL}")

add_executable(pico_btclient
    src/main.cpp
    src/device.cpp
    src/btutils.cpp
    src/sm/setup.cpp
)

target_include_directories(pico_btclient PUBLIC include)
target_link_libraries(pico_btclient PRIVATE
    pico_cyw43_arch_lwip_threadsafe_background
    pico_btstack_ble
    pico_btstack_classic
    pico_btstack_cyw43
    pico_multicore
    pico_stdlib
)
target_compile_options(pico_btclient PRIVATE "-Wno-psabi")
target_compile_definitions(pico_btclient PRIVATE 
#     "WIFI_SSID=\"$ENV{WIFI_SSID}\""
#     "WIFI_PASSWORD=\"$ENV{WIFI_PASSWORD}\""
    "LOG_LEVEL=$ENV{LOG_LEVEL}"
    "RUNNING_AS_CLIENT=1"
#     "LAT=$ENV{LAT}"
#     "LNG=$ENV{LNG}"
#     "TIMEZONE=\"$ENV{TIMEZONE}\""
#     "WEEWX_URL=\"$ENV{WEEWX_URL}\""
)
target_link_options(pico_btclient PRIVATE "-Wl,--print-memory-usage")

pico_enable_stdio_usb(pico_btclient 0)
pico_enable_stdio_uart(pico_btclient 1)
pico_add_extra_outputs(pico_btclient)
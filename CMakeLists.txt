cmake_minimum_required(VERSION 3.16)
project(FirewallDaemon VERSION 1.0.0 LANGUAGES CXX)

# Ustaw standard C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Opcje kompilacji
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -O2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DDEBUG")

# Znajdź wymagane pakiety
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Znajdź libnl i libnftnl
pkg_check_modules(LIBNL REQUIRED libnl-3.0)
pkg_check_modules(LIBNFTNL REQUIRED libnftnl)

# Znajdź DBus
pkg_check_modules(DBUS REQUIRED dbus-1)

# Znajdź systemd (opcjonalnie)
pkg_check_modules(SYSTEMD libsystemd)
if(SYSTEMD_FOUND)
    add_definitions(-DHAVE_SYSTEMD)
endif()

# Katalogi źródłowe
set(SOURCES
    src/daemon/main.cpp
    src/daemon/DaemonCore.cpp
    src/daemon/Logger.cpp
    src/netfilter/NetfilterBackend.cpp
    src/netfilter/ConntrackMonitor.cpp
    src/dbus/DbusInterface.cpp
    src/dbus/FirewallService.cpp
)

# Utwórz wykonywalny plik
add_executable(firewall-daemon ${SOURCES})

# Ustaw katalogi nagłówków
target_include_directories(firewall-daemon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBNL_INCLUDE_DIRS}
    ${LIBNFTNL_INCLUDE_DIRS}
    ${DBUS_INCLUDE_DIRS}
)

# Połącz biblioteki
target_link_libraries(firewall-daemon
    ${LIBNL_LIBRARIES}
    ${LIBNFTNL_LIBRARIES}
    ${DBUS_LIBRARIES}
    Threads::Threads
)

# Dodaj systemd jeśli dostępne
if(SYSTEMD_FOUND)
    target_link_libraries(firewall-daemon ${SYSTEMD_LIBRARIES})
    target_include_directories(firewall-daemon PRIVATE ${SYSTEMD_INCLUDE_DIRS})
endif()

# Ustaw flagi linkowania
target_link_directories(firewall-daemon PRIVATE
    ${LIBNL_LIBRARY_DIRS}
    ${LIBNFTNL_LIBRARY_DIRS}
    ${DBUS_LIBRARY_DIRS}
)

# Instalacja
install(TARGETS firewall-daemon DESTINATION bin)
install(FILES systemd/firewall-daemon.service DESTINATION lib/systemd/system)

# Plik konfiguracyjny
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/firewall-daemon.conf.in
    ${CMAKE_CURRENT_BINARY_DIR}/firewall-daemon.conf
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/firewall-daemon.conf DESTINATION etc/firewall-daemon)

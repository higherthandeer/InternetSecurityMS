#cmake_minimum_required(VERSION 3.28)
#project(netSecurity)
cmake_minimum_required(VERSION 3.13)
project(netSecurity C)

set(CMAKE_C_STANDARD 99)

#set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

link_libraries(nids)
link_libraries(net)
#link_libraries(pcap)
#link_libraries(clntsh)
link_libraries(gthread-2.0)
link_libraries(glib-2.0)
link_libraries(z)

add_executable(netSecurity main.c data_queue.h data_queue.c http_hash.h http_hash.c actrie.h actrie.c change.h change.c
        actrie.c
)
target_link_libraries(netSecurity ${PCAP_LIBRARIES} ${NIDS_LIBRARIES})
target_include_directories(netSecurity PRIVATE ${PCAP_INCLUDE_DIRS} nids pcap gthread-2.0 glib-2.0 pthread z)


cmake_minimum_required(VERSION 3.18)
project(intune-bof-pe C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message("-- Building for ${CMAKE_C_COMPILER_ID} compiler")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link.ld)
    set(ARCH x64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link32.ld)
    set(ARCH x86)
endif()

include_directories(${CMAKE_SOURCE_DIR}/beacon/)
include_directories(${CMAKE_SOURCE_DIR}/common/)

add_subdirectory(beacon)
add_subdirectory(race)
add_subdirectory(exchange)
add_subdirectory(apps)
add_subdirectory(checkin)

# <arch>/ holds the standalone build (exe + beacon.dll)
install(TARGETS beacon race exchange apps checkin
    RUNTIME DESTINATION ${ARCH}
    LIBRARY DESTINATION ${ARCH}
    ARCHIVE EXCLUDE_FROM_ALL)

# pe/ holds the PE named the way OC2 resolves BOFs: <name>.<arch>.o
install(FILES $<TARGET_FILE:race>     DESTINATION pe RENAME race.${ARCH}.o)
install(FILES $<TARGET_FILE:exchange> DESTINATION pe RENAME exchange.${ARCH}.o)
install(FILES $<TARGET_FILE:apps>     DESTINATION pe RENAME apps.${ARCH}.o)
install(FILES $<TARGET_FILE:checkin>  DESTINATION pe RENAME checkin.${ARCH}.o)

install(FILES
    ${CMAKE_SOURCE_DIR}/dist/ost/intune_race_bof.s1.py
    ${CMAKE_SOURCE_DIR}/dist/ost/intune_exchange_bof.s1.py
    ${CMAKE_SOURCE_DIR}/dist/ost/intune_apps_bof.s1.py
    ${CMAKE_SOURCE_DIR}/dist/ost/intune_checkin_bof.s1.py
    DESTINATION ost OPTIONAL)

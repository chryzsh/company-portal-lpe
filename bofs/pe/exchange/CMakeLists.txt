add_library(exchange SHARED exchange_pe.c
    ${CMAKE_SOURCE_DIR}/common/intune_discovery.c
    ${CMAKE_SOURCE_DIR}/common/intune_http.c)
set_target_properties(exchange PROPERTIES PREFIX "")

target_include_directories(exchange PRIVATE ${CMAKE_SOURCE_DIR}/beacon ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(exchange beacon -lwinhttp -lcrypt32)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(exchange PRIVATE /GS- /MT)
    target_link_options(exchange PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(exchange PRIVATE /SAFESEH)
    endif()
else()
    target_link_options(exchange PRIVATE -static -T${LINK_SCRIPT} -Wl,--strip-debug)
endif()

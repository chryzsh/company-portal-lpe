add_library(apps SHARED apps_pe.c
    ${CMAKE_SOURCE_DIR}/common/intune_discovery.c
    ${CMAKE_SOURCE_DIR}/common/intune_http.c)
set_target_properties(apps PROPERTIES PREFIX "")

target_include_directories(apps PRIVATE ${CMAKE_SOURCE_DIR}/beacon ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(apps beacon -lwinhttp -lcrypt32)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(apps PRIVATE /GS- /MT)
    target_link_options(apps PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(apps PRIVATE /SAFESEH)
    endif()
else()
    target_link_options(apps PRIVATE -static -T${LINK_SCRIPT} -Wl,--strip-debug)
endif()

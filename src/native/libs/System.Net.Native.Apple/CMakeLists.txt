project(System.Net.Native.Apple C)

include(${CMAKE_CURRENT_LIST_DIR}/extra_libs.cmake)

set(NATIVE_LIBS_EXTRA)
append_extra_network_apple_libs(NATIVE_LIBS_EXTRA)

set(NATIVE_NETWORK_SOURCES
    pal_networking.m
    pal_networking_tls.m
)

if (CLR_CMAKE_TARGET_MACCATALYST)
    add_definitions(-DTARGET_MACCATALYST)
endif()

if (CLR_CMAKE_TARGET_IOS)
    add_definitions(-DTARGET_IOS)
endif()

if (CLR_CMAKE_TARGET_TVOS)
    add_definitions(-DTARGET_TVOS)
endif()

if (GEN_SHARED_LIB)
    add_library(System.Net.Native.Apple
        SHARED
        ${NATIVE_NETWORK_SOURCES}
        ${VERSION_FILE_PATH}
    )
endif()

if (NOT GEN_SHARED_LIB AND NOT CLR_CMAKE_TARGET_MACCATALYST AND NOT CLR_CMAKE_TARGET_IOS AND NOT CLR_CMAKE_TARGET_TVOS)
    set(NATIVE_NETWORK_SOURCES ${NATIVE_NETWORK_SOURCES} entrypoints.c)
endif()

add_library(System.Net.Native.Apple-Static
    STATIC
    ${NATIVE_NETWORK_SOURCES}
)

set_target_properties(System.Net.Native.Apple-Static PROPERTIES OUTPUT_NAME System.Net.Native.Apple CLEAN_DIRECT_OUTPUT 1)

if (GEN_SHARED_LIB)
    target_link_libraries(System.Net.Native.Apple
        PRIVATE
        ${NATIVE_LIBS_EXTRA}
    )

    if (NOT CLR_CMAKE_TARGET_MACCATALYST AND NOT CLR_CMAKE_TARGET_IOS AND NOT CLR_CMAKE_TARGET_TVOS)
        add_custom_command(TARGET System.Net.Native.Apple POST_BUILD
            COMMENT "Verifying System.Net.Native.Apple points against entrypoints.c "
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../verify-entrypoints.sh
                $<TARGET_FILE:System.Net.Native.Apple>
                ${CMAKE_CURRENT_SOURCE_DIR}/entrypoints.c
                ${CMAKE_NM}
            VERBATIM
        )
    endif()
endif()

if (GEN_SHARED_LIB)
    install_with_stripped_symbols (System.Net.Native.Apple PROGRAMS .)
endif()

install (TARGETS System.Net.Native.Apple-Static DESTINATION ${STATIC_LIB_DESTINATION} COMPONENT libs)

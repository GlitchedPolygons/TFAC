cmake_minimum_required(VERSION 3.10)
project(TFAC C)

set(CMAKE_C_STANDARD 11)

option(${PROJECT_NAME}_DLL "Use as a DLL." OFF)
option(${PROJECT_NAME}_BUILD_DLL "Build as a DLL." OFF)
option(${PROJECT_NAME}_PACKAGE "Build the library and package it into a .tar.gz after successfully building." OFF)

set(${PROJECT_NAME}_MAJOR 1)
set(${PROJECT_NAME}_MINOR 0)
set(${PROJECT_NAME}_PATCH 0)
set(${PROJECT_NAME}_VERSION_STRING "${${PROJECT_NAME}_MAJOR}.${${PROJECT_NAME}_MINOR}.${${PROJECT_NAME}_PATCH}")

set(${PROJECT_NAME}_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(${PROJECT_NAME}_SRC
        src/base32.c
        src/base32.h
        src/picohash.h
        src/tfac.c
        src/tfac.h)

if (${${PROJECT_NAME}_BUILD_DLL})
    add_compile_definitions("${PROJECT_NAME}_BUILD_DLL=1")
    set(${PROJECT_NAME}_DLL ON)
endif ()

if (${${PROJECT_NAME}_DLL})
    add_compile_definitions("${PROJECT_NAME}_DLL=1")
endif ()

add_library(${PROJECT_NAME} ${${PROJECT_NAME}_SRC})
add_executable(${PROJECT_NAME}_cli ${${PROJECT_NAME}_SRC} ${CMAKE_CURRENT_LIST_DIR}/src/tfac_cli.c)

if (${${PROJECT_NAME}_BUILD_DLL} OR BUILD_SHARED_LIBS)
    set_target_properties(${PROJECT_NAME}
            PROPERTIES
            VERSION ${${PROJECT_NAME}_VERSION_STRING}
            SOVERSION ${${PROJECT_NAME}_MAJOR}
            )
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
    target_link_libraries(${PROJECT_NAME}_cli PUBLIC bcrypt)
endif ()

target_include_directories(${PROJECT_NAME} PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR})

if (${${PROJECT_NAME}_PACKAGE})
    set(${PROJECT_NAME}_PKG ${PROJECT_NAME})

    set_target_properties("${PROJECT_NAME}" PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"

            ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"

            ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    set_target_properties(${PROJECT_NAME}_cli PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    string(TOLOWER "${PROJECT_NAME}-${${PROJECT_NAME}_VERSION_STRING}-${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz" ${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME)

    add_custom_command(TARGET ${${PROJECT_NAME}_PKG}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy ${CMAKE_CURRENT_LIST_DIR}/src/tfac.h "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/include/tfac.h"
            )

    add_custom_command(TARGET ${${PROJECT_NAME}_PKG}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E tar "czvf" ${${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME} ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}
            )
endif ()
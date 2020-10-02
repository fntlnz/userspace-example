cmake_minimum_required (VERSION 2.6)

project(userspace-example)

if(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
endif()

option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)

if(MUSL_OPTIMIZED_BUILD)
  set(MUSL_OPTIMIZED_BUILD_FLAGS "-static -Os -DMUSL_OPTIMIZED")
endif()


add_definitions(-DUDIG)
set(CMAKE_C_FLAGS_DEBUG "-Og -g -D_DEBUG -Wall ${MUSL_OPTIMIZED_BUILD_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Wall ${MUSL_OPTIMIZED_BUILD_FLAGS}")

if(NOT SYSDIG_DIR)
	SET(SYSDIG_DIR ../sysdig)
endif()

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${SYSDIG_DIR}/driver)
include_directories(${SYSDIG_DIR}/userspace/common)
include_directories(${SYSDIG_DIR}/userspace/libscap)

add_executable(userspace-example
    main.c
    userspace_compat.c
    ${SYSDIG_DIR}/driver/dynamic_params_table.c
    ${SYSDIG_DIR}/driver/event_table.c
    ${SYSDIG_DIR}/driver/flags_table.c
    ${SYSDIG_DIR}/driver/ppm_events.c
    ${SYSDIG_DIR}/driver/ppm_fillers.c
    ${SYSDIG_DIR}/driver/fillers_table.c
    ${SYSDIG_DIR}/driver/syscall_table.c
    ${SYSDIG_DIR}/userspace/libscap/scap_udig.c
)

target_link_libraries(userspace-example rt)

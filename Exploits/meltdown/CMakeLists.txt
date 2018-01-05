cmake_minimum_required(VERSION 3.8.0)

project (meltdown)

set(CMAKE_BUILD_TYPE Release)
#set (CMAKE_CXX_STANDARD 11)

set(
	CMAKE_CXX_LINK_FLAGS 
)

add_executable(
    meltdown
    ${meltdown_SOURCE_DIR}/src/poc.c
)

TARGET_LINK_LIBRARIES(
    meltdown
)

install(TARGETS meltdown DESTINATION /usr/local/bin)

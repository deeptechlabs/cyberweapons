
find_program(VALGRIND valgrind DOC "Valgrind executable")

if( VALGRIND )
    set(VALGRIND_MEMCHECK_FLAGS --tool=memcheck
                                --track-origins=yes
                                --leak-check=full
                                --error-exitcode=1
                                --show-leak-kinds=all
                                --suppressions=${CMAKE_SOURCE_DIR}/cmake/valgrind.suppressions
                                )
    message(STATUS "Valgrind found")
else()
    message(STATUS "Valgrind not found")
endif()


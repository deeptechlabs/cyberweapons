subdirs("keygen")

add_library(keygen-options Options.c)
add_library(keygen-output Output.c)
target_compile_definitions(keygen-output PRIVATE -DKEYGEN_VERSION="${PROJECT_VERSION}")

add_executable(keygen Main.c)
set_target_properties(keygen PROPERTIES RUNTIME_OUTPUT_NAME "keygen"
                                        RUNTIME_OUTPUT_DIRECTORY "bin"
                                        )
target_link_libraries(keygen keygen-options keygen-output keygen-lib)


if( VALGRIND )
    add_custom_target(memcheck ${VALGRIND} ${VALGRIND_MEMCHECK_FLAGS}
                        $<TARGET_FILE:keygen> -sl 6000 1> /dev/null
                        COMMENT "Memchecking executable\n\n"
                        VERBATIM
                        )
endif()

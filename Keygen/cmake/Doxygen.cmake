
message(STATUS "Doxyfile ${DOXYFILE}")

if( ${DOXYFILE} )
    set(DOXYFILE_FILE "${CMAKE_SOURCE_DIR}/Doxyfile")

    configure_file("${CMAKE_MODULE_PATH}/Doxyfile.in" ${DOXYFILE_FILE} @ONLY)
endif()
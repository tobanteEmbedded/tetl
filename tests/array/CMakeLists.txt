project(array)

tetl_add_test(${PROJECT_NAME} array)
tetl_add_test(${PROJECT_NAME} dynamic_array)
tetl_add_test(${PROJECT_NAME} uninitialized_array)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    file(GLOB files "${PROJECT_SOURCE_DIR}/verify/*.verify.cpp")
    foreach(file ${files})
        get_filename_component(stem ${file} NAME_WLE)
        add_test(
            NAME
                "${PROJECT_NAME}.hpp: clang-verify ${stem}"
            COMMAND
                ${CMAKE_CXX_COMPILER} "-Xclang" "-verify" "-c"
                "-std=c++${CMAKE_CXX_STANDARD}"
                "-I" "${CMAKE_SOURCE_DIR}/include"
                "${file}"
            WORKING_DIRECTORY
                ${CMAKE_SOURCE_DIR}
            COMMAND_EXPAND_LISTS
        )
    endforeach()
endif()

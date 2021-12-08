project(experimental_testing)

if(NOT ${CMAKE_CROSSCOMPILING})
    add_executable(${PROJECT_NAME}
        test_main.cpp
        test_test_case.cpp
    )
    add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            tobanteEmbedded::etl
            tobanteEmbedded::CompilerOptions
            tobanteEmbedded::CompilerWarnings
            tobanteEmbedded::CodeCoverage
    )
endif()
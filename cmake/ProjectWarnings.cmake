    # Link this 'library' to use the following warnings
    add_library(project_warnings INTERFACE)
    add_library(tobanteAudio::CompilerWarnings ALIAS project_warnings)

    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      target_compile_options(project_warnings
                            INTERFACE
                            -Wall
                            -Wextra # reasonable and standard
                            -Wshadow # warn the user if a variable declaration shadows one from a
                                    # parent context
                            -Wnon-virtual-dtor # warn the user if a class with virtual functions has a
                                              # non-virtual destructor. This helps catch hard to
                                              # track down memory errors
                            -Wold-style-cast # warn for c-style casts
                            -Wcast-align # warn for potential performance problem casts
                            -Wunused # warn on anything being unused
                            -Woverloaded-virtual # warn if you overload (not override) a virtual
                                                # function
                            -Wpedantic # warn if non-standard C++ is used
                            -Wconversion # warn on type conversions that may lose data
                            -Wsign-conversion # warn on sign conversions
                            -Wduplicate-enum
                            -Wnull-dereference # warn if a null dereference is detected
                            -Wdouble-promotion # warn if float is implicit promoted to double
                            -Wformat=2 # warn on security issues around functions that format output
                                      # (ie printf)
      )
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
      target_compile_options(project_warnings
                            INTERFACE
                            -Wall
                            -Wextra # reasonable and standard
                            -Wshadow # warn the user if a variable declaration shadows one from a
                                    # parent context
                            -Wnon-virtual-dtor # warn the user if a class with virtual functions has a
                                              # non-virtual destructor. This helps catch hard to
                                              # track down memory errors
                            -Wold-style-cast # warn for c-style casts
                            -Wcast-align # warn for potential performance problem casts
                            -Wunused # warn on anything being unused
                            -Woverloaded-virtual # warn if you overload (not override) a virtual
                                                # function
                            -Wpedantic # warn if non-standard C++ is used
                            -Wconversion # warn on type conversions that may lose data
                            -Wsign-conversion # warn on sign conversions
                            -Wmisleading-indentation # warn if identation implies blocks where blocks
                                                    # do not exist
                            -Wduplicated-cond # warn if if / else chain has duplicated conditions
                            # -Wduplicated-branches # warn if if / else branches have duplicated code
                            -Wlogical-op # warn about logical operations being used where bitwise were
                                        # probably wanted
                            -Wnull-dereference # warn if a null dereference is detected
                            -Wuseless-cast # warn if you perform a cast to the same type
                            -Wdouble-promotion # warn if float is implicit promoted to double
                            -Wformat=2 # warn on security issues around functions that format output
                                      # (ie printf)
      )
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
      target_compile_options(project_warnings INTERFACE /W4 /WX "/permissive-")
    endif()
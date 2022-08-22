project(examples)

foreach(_target
  "algorithm"
  "all_headers"
  "array"
  "bitset"
  "cassert"
  "chrono"
  "cmath"
  "memory"
  "numeric"
  "optional"
  "set"
  "source_location"
  "string"
  "tuple"
  "type_traits"
  "utility"
  "vector"
)
  add_executable(${_target} "${_target}.cpp")
  target_link_libraries(${_target}
    PRIVATE
      tetl::etl
      tetl::compiler_options
      tetl::compiler_warnings
      tetl::code_coverage
  )
  add_test(NAME "example_${_target}" COMMAND ${_target})
endforeach()

set_tests_properties(example_cassert PROPERTIES WILL_FAIL TRUE)

add_subdirectory(experimental)

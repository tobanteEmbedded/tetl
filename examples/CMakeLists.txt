project(examples)

foreach(_target
  "algorithm"
  "array"
  "bitset"
  "cassert"
  "chrono"
  "map"
  "memory"
  "numeric"
  "optional"
  "set"
  "string"
  "tuple"
  "type_traits"
  "utility"
  "vector"
)
  add_executable(${_target} "${_target}.cpp")
  target_link_libraries(${_target}
    PRIVATE
      tobanteEmbedded::etl
      tobanteEmbedded::CompilerOptions
      tobanteEmbedded::CompilerWarnings
      tobanteEmbedded::CodeCoverage
  )
  add_test("example_${_target}" ${_target})
endforeach()

add_subdirectory(experimental)
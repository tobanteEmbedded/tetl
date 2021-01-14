project(examples)

foreach(_target
  "algorithm"
  "array"
  "chrono"
  "map"
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
      tobanteAudio::etl
      tobanteAudio::CompilerOptions
      tobanteAudio::CompilerWarnings
      tobanteAudio::CodeCoverage
  )
  add_test("example_${_target}" ${_target})
endforeach()

add_subdirectory(experimental)
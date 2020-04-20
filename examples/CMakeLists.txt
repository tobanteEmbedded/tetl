project(examples)

foreach(_target 
  "algorithm"
  "array"
  "numeric"
  "string"
  "tuple"
  "type_traits"
  "vector"
)
  add_executable(${_target} "${_target}.cpp")
  target_link_libraries(${_target} PRIVATE tobanteAudio::etl tobanteAudio::CompilerOptions tobanteAudio::CompilerWarnings)
  add_test("example_${_target}" ${_target})
endforeach()

add_subdirectory(experimental)
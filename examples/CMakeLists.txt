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
  target_compile_features(${_target} PRIVATE cxx_std_17)
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
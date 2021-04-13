project(examples-experimental)

foreach(_target "stm32_rtos")
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

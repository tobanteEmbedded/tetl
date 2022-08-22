project(examples-experimental)

foreach(_target "stm32_freertos")
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

project(cmath-tests)

foreach(_target
    "cos"
    "sin"
)
  add_executable("test_cmath_${_target}" "${_target}.cpp")
  add_test(NAME "test_cmath_${_target}" COMMAND "test_cmath_${_target}")
  target_link_libraries("test_cmath_${_target}"
    PRIVATE
      tobanteEmbedded::etl
      tobanteEmbedded::CompilerOptions
      tobanteEmbedded::CompilerWarnings
      tobanteEmbedded::CodeCoverage
  )
endforeach()
add_library(compiler_warnings INTERFACE)
add_library(tetl::compiler_warnings ALIAS compiler_warnings)

if (MSVC)
  target_compile_options(compiler_warnings
    INTERFACE
      /W3
      /wd4723 # potential divide by 0
      $<$<BOOL:${TETL_BUILD_WERROR}>:/WX>
  )
else ()
  target_compile_options(compiler_warnings
    INTERFACE
      -Wall
      -Wextra
      -Wpedantic
      $<$<BOOL:${TETL_BUILD_WERROR}>:-Werror>

      -Wcast-align
      -Wcast-qual
      -Wdouble-promotion
      -Wmissing-field-initializers
      -Wnarrowing
      -Woverloaded-virtual
      -Wreorder
      -Wshadow
      -Wsign-compare
      -Wsign-promo
      -Wstrict-aliasing
      -Wswitch-enum
      -Wuninitialized
      -Wunreachable-code
      -Wunused-parameter
      -Wzero-as-null-pointer-constant
      -Wsign-conversion

      $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:
          -Wbool-conversion
          -Wconditional-uninitialized
          -Wconstant-conversion
          -Wconversion
          -Wextra-semi
          -Winconsistent-missing-destructor-override
          -Wint-conversion
          -Wnullable-to-nonnull-conversion
          -Wshadow-all
          -Wshift-sign-overflow
          -Wshorten-64-to-32
          -Wunused-private-field
          -Wreturn-type

          $<$<BOOL:${TETL_BUILD_WEVERYTHING}>:
            -Weverything
            -Wno-c++98-compat-pedantic
            -Wno-c++20-compat
            -Wno-ctad-maybe-unsupported
            -Wno-float-equal
            -Wno-padded
            -Wno-unused-member-function
            -Wno-unsafe-buffer-usage
            -Wno-weak-vtables
          >
      >


      $<$<CXX_COMPILER_ID:GNU>:
        -Wmisleading-indentation
        -Wlogical-op
        -Wduplicated-branches
        -Wduplicated-cond
      >
  )
endif (MSVC)

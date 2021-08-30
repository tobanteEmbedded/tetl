/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CASSERT_MACRO_HPP
#define TETL_CASSERT_MACRO_HPP

#include "etl/_config/all.hpp"

#include "etl/_version/implementation.hpp"
#include "etl/_warning/ignore_unused.hpp"

#if __has_include(<stdlib.h>)
    #include <stdlib.h>

    #include "etl/_config/_workarounds/001_avr_macros.hpp" // For AVR macros
#else
inline auto exit(int /*ignore*/) -> void { }
#endif

namespace etl {
/// \brief Payload for an assertion.
struct assert_msg {
    int line {};
    char const* file { nullptr };
    char const* func { nullptr };
    char const* expression { nullptr };
};

} // namespace etl

namespace etl {
#if defined(TETL_CUSTOM_ASSERT_HANDLER)

/// \brief This functions needs to be implemented if you enabled the
/// `TETL_CUSTOM_ASSERT_HANDLER` macro. Rebooting the chip is probably the
/// best idea, because you can not recover from any of the exceptional cases in
/// the library.
[[noreturn]] auto tetl_assert_handler(assert_msg const& msg) -> void;
#else

#endif

/// \brief The default assert handler. This will be called, if an assertion
/// is triggered at runtime.
[[noreturn]] inline auto tetl_default_assert_handler(assert_msg const& msg)
    -> void
{
    etl::ignore_unused(msg);
    ::exit(1); // NOLINT
}

namespace detail {
[[noreturn]] inline auto tetl_call_assert_handler(assert_msg const& msg) -> void
{
#if defined(TETL_CUSTOM_ASSERT_HANDLER)
    etl::tetl_assert_handler(msg);
#else
    etl::tetl_default_assert_handler(msg);
#endif
}

} // namespace detail

} // namespace etl

#if not defined(TETL_ASSERT)
    #if !defined(TETL_NDEBUG) || (TETL_NDEBUG == 0)
  /// \brief Assertion macro with customizable runtime behavior
        #define TETL_ASSERT(exp)                                               \
            do {                                                               \
                if (TETL_UNLIKELY((exp) == false)) {                           \
                    /* TETL_DEBUG_TRAP(); */                                   \
                    auto const msg = etl::assert_msg {                         \
                        __LINE__, /*line of assertion*/                        \
                        __FILE__, /*source file*/                              \
                        etl::is_hosted() ? TETL_BUILTIN_FUNCTION() : nullptr,  \
                        etl::is_hosted() ? TETL_PP_STRINGIFY(exp) : nullptr,   \
                    };                                                         \
                    etl::detail::tetl_call_assert_handler(msg);                \
                }                                                              \
            } while (false)
    #else
        #define TETL_ASSERT(exp)
    #endif // !defined(TETL_NDEBUG)
#endif     // not defined(TETL_ASSERT)

#endif // TETL_CASSERT_MACRO_HPP
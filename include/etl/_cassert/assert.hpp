// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CASSERT_ASSERT_HPP
#define TETL_CASSERT_ASSERT_HPP

#include <etl/_config/all.hpp>

#include <etl/_utility/ignore_unused.hpp>
#include <etl/_version/implementation.hpp>

#if __has_include(<stdlib.h>)
    #include <stdlib.h>

    #include <etl/_config/_workarounds/001_avr_macros.hpp> // For AVR macros
#else
inline auto exit(int /*ignore*/) -> void { }
#endif

namespace etl {
/// \brief Payload for an assertion.
struct assert_msg {
    int line{};
    char const* file{nullptr};
    char const* func{nullptr};
    char const* expression{nullptr};
};

} // namespace etl

namespace etl {
#if defined(TETL_ENABLE_CUSTOM_ASSERT_HANDLER)

template <typename Assertion>
[[noreturn]] auto assert_handler(Assertion const& msg) -> void; // NOLINT

#else

template <typename Assertion>
[[noreturn]] auto assert_handler(Assertion const& msg) -> void // NOLINT
{
    etl::ignore_unused(msg);
    ::exit(1); // NOLINT
}

#endif

} // namespace etl

#define TETL_ASSERT_IMPL(...)                                                                                          \
    do {                                                                                                               \
        if (not(__VA_ARGS__)) [[unlikely]] {                                                                           \
            /* TETL_DEBUG_TRAP(); */                                                                                   \
            etl::assert_handler(                                                                                       \
                etl::assert_msg{                                                                                       \
                    .line       = __LINE__,                                                                            \
                    .file       = __FILE__,                                                                            \
                    .func       = etl::is_hosted() ? TETL_BUILTIN_FUNCTION() : nullptr,                                \
                    .expression = etl::is_hosted() ? TETL_STRINGIFY((__VA_ARGS__)) : nullptr,                          \
                }                                                                                                      \
            );                                                                                                         \
        }                                                                                                              \
    } while (false)

#if not defined(TETL_NDEBUG) or (TETL_NDEBUG == 0) or defined(TETL_ENABLE_ASSERTIONS)
    #define TETL_ASSERT(...) TETL_ASSERT_IMPL(__VA_ARGS__)
#else
    #define TETL_ASSERT(...)
#endif

#endif // TETL_CASSERT_ASSERT_HPP

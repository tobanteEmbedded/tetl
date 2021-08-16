// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_ASSERT_MACRO_HPP
#define TETL_ASSERT_MACRO_HPP

#include "etl/_config/debug_trap.hpp"
#include "etl/_version/implementation.hpp"
#include "etl/_warning/ignore_unused.hpp"

#if __has_include(<stdlib.h>)
#include <stdlib.h>
#else
auto exit(int /*ignore*/) -> void { }
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
auto tetl_assert_handler(assert_msg const& msg) -> void;
#else

#endif

/// \brief The default assert handler. This will be called, if an assertion
/// is triggered at runtime.
inline auto tetl_default_assert_handler(assert_msg const& msg) -> void
{
    ::etl::ignore_unused(msg);
    ::exit(1); // NOLINT
}

namespace detail {
inline auto tetl_call_assert_handler(assert_msg const& msg) -> void
{
#if defined(TETL_CUSTOM_ASSERT_HANDLER)
    ::etl::tetl_assert_handler(msg);
#else
    ::etl::tetl_default_assert_handler(msg);
#endif
}

} // namespace detail

} // namespace etl

#if not defined(TETL_ASSERT)
#if !defined(TETL_NDEBUG) || (TETL_NDEBUG == 0)
/// \brief Assertion macro with customizable runtime behavior
#define TETL_ASSERT(exp)                                                       \
    do {                                                                       \
        if (TETL_UNLIKELY((exp) == false)) {                                   \
            /* TETL_DEBUG_TRAP(); */                                           \
            auto const msg = ::etl::assert_msg {                               \
                __LINE__, /*line of assertion*/                                \
                __FILE__, /*source file*/                                      \
                ::etl::is_hosted() ? TETL_BUILTIN_FUNCTION() : nullptr,        \
                ::etl::is_hosted() ? TETL_PP_STRINGIFY(exp) : nullptr,         \
            };                                                                 \
            ::etl::detail::tetl_call_assert_handler(msg);                      \
        }                                                                      \
    } while (false)
#else
#define TETL_ASSERT(exp)
#endif // !defined(TETL_NDEBUG)
#endif // not defined(TETL_ASSERT)

#endif // TETL_ASSERT_MACRO_HPP
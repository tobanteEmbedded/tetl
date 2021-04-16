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

#ifndef TETL_CASSERT_HPP
#define TETL_CASSERT_HPP

#include "etl/version.hpp"

#if __has_include(<assert.h>)
#include <assert.h>
#else
#ifndef assert
#define assert(x)
#endif
#endif

#if __has_include(<stdlib.h>)
#include <stdlib.h>
#else
auto exit() -> void { }
#endif

#include "etl/warning.hpp"
namespace etl
{
/// \brief Payload for an assertion.
struct assert_msg
{
  int line {};
  char const* file {nullptr};
  char const* func {nullptr};
  char const* expression {nullptr};
};

}  // namespace etl

namespace etl
{
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
  ::exit(1);
}

namespace detail
{
inline auto tetl_call_assert_handler(assert_msg const& msg) -> void
{
#if defined(TETL_CUSTOM_ASSERT_HANDLER)
  ::etl::tetl_assert_handler(msg);
#else
  ::etl::tetl_default_assert_handler(msg);
#endif
}

}  // namespace detail

}  // namespace etl

#if not defined(TETL_TO_STR)
#define TETL_TO_STR_IMPL(s) #s
#define TETL_TO_STR(s) TETL_TO_STR_IMPL(s)
#endif  // TETL_TO_STR

#if not defined(TETL_ASSERT)
/// \brief Assertion macro with customizable runtime behavior
#define TETL_ASSERT(exp)                                                       \
  do {                                                                         \
    if (!(exp))                                                                \
    {                                                                          \
      auto const msg = ::etl::assert_msg {                                     \
        __LINE__, __FILE__,                                                    \
        nullptr, /*The function name causes code bloat.  */                    \
        nullptr, /*The stringified expression causes code bloat.  */           \
      };                                                                       \
      ::etl::detail::tetl_call_assert_handler(msg);                            \
    }                                                                          \
  } while (false)
#endif  // TETL_ASSERT

#endif  // TETL_CASSERT_HPP

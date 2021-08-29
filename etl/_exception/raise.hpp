/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_EXCEPTION_RAISE_HPP
#define TETL_EXCEPTION_RAISE_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_config/attributes.hpp"
#include "etl/_source_location/source_location.hpp"

namespace etl {
#if TETL_CPP_STANDARD >= 20
template <typename E>
[[noreturn]] TETL_NO_INLINE TETL_COLD constexpr auto raise(char const* msg,
    etl::source_location const loc = etl::source_location::current()) -> void
{
    auto const assertion = etl::assert_msg {
        static_cast<int>(loc.line()),
        loc.file_name(),
        loc.function_name(),
        E { msg }.what(),
    };
    detail::tetl_call_assert_handler(assertion);
}

#else

template <typename E>
[[noreturn]] TETL_NO_INLINE TETL_COLD constexpr auto raise(char const* msg)
    -> void
{
    detail::tetl_call_assert_handler(etl::assert_msg {
        0,
        nullptr,
        nullptr,
        E { msg }.what(),
    });
}
#endif
} // namespace etl

#endif // TETL_EXCEPTION_RAISE_HPP
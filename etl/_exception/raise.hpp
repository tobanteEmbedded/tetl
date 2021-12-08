/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_EXCEPTION_RAISE_HPP
#define TETL_EXCEPTION_RAISE_HPP

#include "etl/_config/all.hpp"

#include "etl/_cassert/macro.hpp"
#include "etl/_exception/exception.hpp"
#include "etl/_source_location/source_location.hpp"

namespace etl {

#if TETL_CPP_STANDARD >= 20
template <typename Exception>
[[noreturn]] TETL_NO_INLINE TETL_COLD auto raise(
    char const* msg, etl::source_location const loc = etl::source_location::current()) -> void
{
    #if defined(TETL_ENABLE_CUSTOM_EXCEPTION_HANDLER)
    (void)loc;
    etl::tetl_exception_handler(Exception { msg });
    #else
    detail::tetl_call_assert_handler(etl::assert_msg {
        static_cast<int>(loc.line()),
        loc.file_name(),
        loc.function_name(),
        Exception { msg }.what(),
    });
    #endif
}

#else

template <typename Exception>
[[noreturn]] TETL_NO_INLINE TETL_COLD auto raise(char const* msg) -> void
{
    #if defined(TETL_ENABLE_CUSTOM_EXCEPTION_HANDLER)
    etl::tetl_exception_handler(Exception { msg });
    #else
    detail::tetl_call_assert_handler(etl::assert_msg {
        0,
        nullptr,
        nullptr,
        Exception { msg }.what(),
    });
    #endif
}
#endif
} // namespace etl

#endif // TETL_EXCEPTION_RAISE_HPP
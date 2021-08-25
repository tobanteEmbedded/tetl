/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/source_location.hpp"
#include "etl/string_view.hpp"

#include <stdio.h>

auto log(etl::string_view const message,
    etl::source_location const location = etl::source_location::current())
    -> void
{
    ::printf(                                     //
        "file: %s(%u:%u) `%s`: %s\n",             //
        location.file_name(),                     //
        static_cast<unsigned>(location.line()),   //
        static_cast<unsigned>(location.column()), //
        location.function_name(),                 //
        message.data()                            //
    );
}

template <typename T>
auto fun(T x) -> void
{
    log(x);
}

auto main(int /*argc*/, char const** /*argv*/) -> int
{
    log("Hello world!");
    fun("Hello C++20!");
    return 0;
}
// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/source_location.hpp>
    #include <etl/string_view.hpp>
#endif

#include <stdio.h>

static auto log(etl::string_view const message, etl::source_location const location = etl::source_location::current())
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
static auto fun(T x) -> void
{
    log(x);
}

auto main(int /*argc*/, char const** /*argv*/) -> int
{
    log("Hello world!");
    fun("Hello C++23!");
    return 0;
}

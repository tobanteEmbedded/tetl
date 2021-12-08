/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/exception.hpp"

#include "etl/string_view.hpp"

#include "testing/testing.hpp"

auto main() -> int
{
#if defined(__cpp_exceptions)
    try {
        etl::raise<etl::exception>("should fail");
        assert(false);
    } catch (etl::exception const& e) {
        assert(e.what() == etl::string_view { "should fail" });
    }
#endif
    return 0;
}
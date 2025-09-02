// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/exception.hpp>
    #include <etl/string_view.hpp>
#endif

auto main() -> int
{
#if defined(__cpp_exceptions)
    try {
        etl::raise<etl::exception>("should fail");
        CHECK(false);
    } catch (etl::exception const& e) {
        CHECK(e.what() == etl::string_view{"should fail"});
    }
#endif
    return 0;
}

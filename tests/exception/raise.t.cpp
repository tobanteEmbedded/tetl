// SPDX-License-Identifier: BSL-1.0

#include <etl/exception.hpp>

#include <etl/string_view.hpp>

#include "testing/testing.hpp"

auto main() -> int
{
#if defined(__cpp_exceptions)
    try {
        etl::raise<etl::exception>("should fail");
        assert(false);
    } catch (etl::exception const& e) {
        assert(e.what() == etl::string_view {"should fail"});
    }
#endif
    return 0;
}

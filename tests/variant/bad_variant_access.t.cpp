// SPDX-License-Identifier: BSL-1.0

#include "testing/exception.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/exception.hpp>
    #include <etl/variant.hpp>
#endif

namespace {

constexpr auto test() -> bool
{
    CHECK_EXCEPTION_TYPE(etl::bad_variant_access, etl::exception);
    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test());

    return 0;
}

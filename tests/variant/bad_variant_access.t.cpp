// SPDX-License-Identifier: BSL-1.0

#include <etl/variant.hpp>

#include "testing/exception.hpp"
#include "testing/testing.hpp"

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

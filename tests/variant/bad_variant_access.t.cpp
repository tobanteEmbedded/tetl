// SPDX-License-Identifier: BSL-1.0

#include <etl/variant.hpp>

#include "testing/exception.hpp"
#include "testing/testing.hpp"

namespace {

constexpr auto test() -> bool
{
    TEST_EXCEPTION(etl::bad_variant_access, etl::exception);
    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test());
    static_assert(test());

    return 0;
}

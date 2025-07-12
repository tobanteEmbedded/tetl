// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.type_traits;
import etl.variant;
#else
    #include <etl/type_traits.hpp>
    #include <etl/variant.hpp>
#endif

namespace {

constexpr auto test() -> bool
{
    // All instances of monostate compare equal.
    auto const lhs = etl::monostate{};
    auto const rhs = etl::monostate{};

    CHECK(lhs == rhs);
    CHECK(lhs <= rhs);
    CHECK(lhs >= rhs);
    CHECK(not(lhs != rhs));
    CHECK(not(lhs < rhs));
    CHECK(not(lhs > rhs));

    CHECK_NOEXCEPT(lhs == rhs);
    CHECK_NOEXCEPT(lhs <= rhs);
    CHECK_NOEXCEPT(lhs >= rhs);
    CHECK_NOEXCEPT(lhs != rhs);
    CHECK_NOEXCEPT(lhs < rhs);
    CHECK_NOEXCEPT(lhs > rhs);

    CHECK(etl::is_empty_v<etl::monostate>);

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test());

    return 0;
}

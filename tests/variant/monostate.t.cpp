// SPDX-License-Identifier: BSL-1.0

#include <etl/variant.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace {

constexpr auto test() -> bool
{
    // All instances of monostate compare equal.
    auto const lhs = etl::monostate{};
    auto const rhs = etl::monostate{};

    ASSERT(lhs == rhs);
    ASSERT(lhs <= rhs);
    ASSERT(lhs >= rhs);
    ASSERT(not(lhs != rhs));
    ASSERT(not(lhs < rhs));
    ASSERT(not(lhs > rhs));

    ASSERT_NOEXCEPT(lhs == rhs);
    ASSERT_NOEXCEPT(lhs <= rhs);
    ASSERT_NOEXCEPT(lhs >= rhs);
    ASSERT_NOEXCEPT(lhs != rhs);
    ASSERT_NOEXCEPT(lhs < rhs);
    ASSERT_NOEXCEPT(lhs > rhs);

    ASSERT(etl::is_empty_v<etl::monostate>);

    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test());
    static_assert(test());

    return 0;
}

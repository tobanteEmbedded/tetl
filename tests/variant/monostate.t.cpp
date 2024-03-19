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
    CHECK(test());
    static_assert(test());

    return 0;
}

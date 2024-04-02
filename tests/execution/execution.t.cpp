// SPDX-License-Identifier: BSL-1.0

#include <etl/execution.hpp>

#include "testing/testing.hpp"

namespace {
constexpr auto test() -> bool
{
    struct foo { };

    CHECK(etl::is_execution_policy_v<etl::execution::sequenced_policy>);
    CHECK(etl::is_execution_policy_v<etl::execution::unsequenced_policy>);

    CHECK_FALSE(etl::is_execution_policy_v<int>);
    CHECK_FALSE(etl::is_execution_policy_v<float>);
    CHECK_FALSE(etl::is_execution_policy_v<void*>);
    CHECK_FALSE(etl::is_execution_policy_v<foo>);

    CHECK(etl::execution_policy<etl::execution::sequenced_policy>);
    CHECK(etl::execution_policy<etl::execution::unsequenced_policy>);

    CHECK_FALSE(etl::execution_policy<int>);
    CHECK_FALSE(etl::execution_policy<float>);
    CHECK_FALSE(etl::execution_policy<void*>);
    CHECK_FALSE(etl::execution_policy<foo>);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}

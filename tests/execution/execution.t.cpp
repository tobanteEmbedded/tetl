// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/execution.hpp>
#endif

namespace {
constexpr auto test() -> bool
{
    struct Foo { };

    CHECK(etl::is_execution_policy_v<etl::execution::sequenced_policy>);
    CHECK(etl::is_execution_policy_v<etl::execution::unsequenced_policy>);

    CHECK_FALSE(etl::is_execution_policy_v<int>);
    CHECK_FALSE(etl::is_execution_policy_v<float>);
    CHECK_FALSE(etl::is_execution_policy_v<void*>);
    CHECK_FALSE(etl::is_execution_policy_v<Foo>);

    CHECK(etl::execution_policy<etl::execution::sequenced_policy>);
    CHECK(etl::execution_policy<etl::execution::unsequenced_policy>);

    CHECK_FALSE(etl::execution_policy<int>);
    CHECK_FALSE(etl::execution_policy<float>);
    CHECK_FALSE(etl::execution_policy<void*>);
    CHECK_FALSE(etl::execution_policy<Foo>);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}

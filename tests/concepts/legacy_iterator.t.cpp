// SPDX-License-Identifier: BSL-1.0

#include <etl/concepts.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    CHECK(etl::referenceable<int>);
    CHECK(etl::referenceable<float>);
    CHECK(etl::referenceable<char const*>);
    CHECK(etl::referenceable<float const>);
    CHECK(etl::referenceable<float const&>);
    CHECK(etl::referenceable<float&>);
    CHECK_FALSE(etl::referenceable<void>);
    CHECK_FALSE(etl::referenceable<void const>);
    CHECK_FALSE(etl::referenceable<void volatile>);
    CHECK_FALSE(etl::referenceable<void const volatile>);

    CHECK(etl::legacy_iterator<char const*>);
    CHECK_FALSE(etl::legacy_iterator<int>);
    CHECK_FALSE(etl::legacy_iterator<void>);

    CHECK(etl::legacy_input_iterator<char const*>);
    CHECK_FALSE(etl::legacy_input_iterator<int>);
    CHECK_FALSE(etl::legacy_input_iterator<void>);

    CHECK(etl::legacy_forward_iterator<char const*>);
    CHECK_FALSE(etl::legacy_forward_iterator<int>);
    CHECK_FALSE(etl::legacy_forward_iterator<void>);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}

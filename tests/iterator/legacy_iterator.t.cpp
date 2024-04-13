// SPDX-License-Identifier: BSL-1.0

#include <etl/concepts.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

namespace {
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

    CHECK(etl::legacy_iterator<char*>);
    CHECK(etl::legacy_iterator<char const*>);
    CHECK_FALSE(etl::legacy_iterator<int>);
    CHECK_FALSE(etl::legacy_iterator<void>);

    CHECK(etl::legacy_input_iterator<char*>);
    CHECK(etl::legacy_input_iterator<char const*>);
    CHECK(etl::legacy_input_iterator<InIter<char*>>);
    CHECK(etl::legacy_input_iterator<InIter<char const*>>);
    CHECK_FALSE(etl::legacy_input_iterator<int>);
    CHECK_FALSE(etl::legacy_input_iterator<void>);

    CHECK(etl::legacy_forward_iterator<char*>);
    CHECK(etl::legacy_forward_iterator<char const*>);
    CHECK(etl::legacy_forward_iterator<FwdIter<char*>>);
    CHECK(etl::legacy_forward_iterator<FwdIter<char const*>>);
    CHECK_FALSE(etl::legacy_forward_iterator<int>);
    CHECK_FALSE(etl::legacy_forward_iterator<void>);

    CHECK(etl::legacy_bidirectional_iterator<char const*>);
    CHECK_FALSE(etl::legacy_bidirectional_iterator<InIter<char*>>);
    CHECK_FALSE(etl::legacy_bidirectional_iterator<InIter<char const*>>);
    CHECK_FALSE(etl::legacy_bidirectional_iterator<FwdIter<char*>>);
    CHECK_FALSE(etl::legacy_bidirectional_iterator<FwdIter<char const*>>);
    CHECK_FALSE(etl::legacy_bidirectional_iterator<int>);
    CHECK_FALSE(etl::legacy_bidirectional_iterator<void>);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}

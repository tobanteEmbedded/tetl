// SPDX-License-Identifier: BSL-1.0

#include <etl/expected.hpp>

#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::is_same_v<etl::unexpect_t, etl::decay_t<decltype(etl::unexpect)>>);
    CHECK(etl::is_default_constructible_v<etl::unexpect_t>);

    auto unex = etl::unexpected{T(42)};
    CHECK(unex.error() == T(42));
    CHECK(etl::is_same_v<decltype(unex.error()), T&>);
    CHECK(etl::is_same_v<decltype(etl::as_const(unex).error()), T const&>);
    CHECK(etl::is_same_v<decltype(etl::move(unex).error()), T&&>);
    CHECK(etl::is_same_v<decltype(etl::move(etl::as_const(unex)).error()), T const&&>);

    auto other = etl::unexpected{T(99)};
    CHECK(other.error() == T(99));

    swap(unex, other);
    CHECK(unex.error() == T(99));
    CHECK(other.error() == T(42));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

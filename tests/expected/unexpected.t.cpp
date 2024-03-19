// SPDX-License-Identifier: BSL-1.0

#include <etl/expected.hpp>

#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::is_same_v<etl::unexpect_t, etl::decay_t<decltype(etl::unexpect)>>);
    assert(etl::is_default_constructible_v<etl::unexpect_t>);

    auto unex = etl::unexpected{T(42)};
    assert(unex.error() == T(42));
    assert(etl::is_same_v<decltype(unex.error()), T&>);
    assert(etl::is_same_v<decltype(etl::as_const(unex).error()), T const&>);
    assert(etl::is_same_v<decltype(etl::move(unex).error()), T&&>);
    assert(etl::is_same_v<decltype(etl::move(etl::as_const(unex)).error()), T const&&>);

    auto other = etl::unexpected{T(99)};
    assert(other.error() == T(99));

    swap(unex, other);
    assert(unex.error() == T(99));
    assert(other.error() == T(42));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<signed char>());
    assert(test<signed short>());
    assert(test<signed int>());
    assert(test<signed long>());
    assert(test<signed long long>());

    assert(test<unsigned char>());
    assert(test<unsigned short>());
    assert(test<unsigned int>());
    assert(test<unsigned long>());
    assert(test<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

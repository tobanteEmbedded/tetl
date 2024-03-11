// SPDX-License-Identifier: BSL-1.0

#include <etl/expected.hpp>

#include <etl/concepts.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T, typename E>
auto test() -> bool
{
    using expected_t = etl::expected<T, E>;

    assert(etl::is_default_constructible_v<expected_t>);
    assert(etl::is_nothrow_default_constructible_v<expected_t>);

    assert(etl::same_as<typename expected_t::value_type, T>);
    assert(etl::same_as<typename expected_t::error_type, E>);
    assert(etl::same_as<typename expected_t::unexpected_type, etl::unexpected<E>>);
    assert(etl::same_as<typename expected_t::template rebind<float>, etl::expected<float, E>>);

    assert(noexcept(etl::declval<expected_t>().has_value()));
    assert(noexcept(static_cast<bool>(etl::declval<expected_t>())));

    auto ex1 = expected_t {};
    assert(ex1.has_value());
    assert(static_cast<bool>(ex1));
    assert(etl::as_const(ex1).has_value());
    assert(static_cast<bool>(etl::as_const(ex1)));
    assert(ex1.value() == 0);
    assert(etl::as_const(ex1).value() == 0);
    assert(ex1.value_or(42.0F) == 0);
    assert(etl::as_const(ex1).value_or(42.0F) == 0);
    assert(expected_t().value() == 0);

    return true;
}

auto test_all() -> bool
{
    assert(test<signed char, int>());
    assert(test<signed short, int>());
    assert(test<signed int, int>());
    assert(test<signed long, int>());
    assert(test<signed long long, int>());

    assert(test<unsigned char, int>());
    assert(test<unsigned short, int>());
    assert(test<unsigned int, int>());
    assert(test<unsigned long, int>());
    assert(test<unsigned long long, int>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}

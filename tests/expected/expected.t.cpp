// SPDX-License-Identifier: BSL-1.0

#include <etl/expected.hpp>

#include <etl/concepts.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {
struct error_class {
    constexpr error_class() = default;
    constexpr explicit error_class(int v) : value(v) { }
    int value {0};

    friend constexpr auto operator==(error_class ec, int v) { return ec.value == v; }
};
} // namespace

template <typename T, typename E>
static auto test() -> bool
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

    auto ex2 = expected_t {etl::in_place, T(42)};
    assert(ex2.has_value());
    assert(static_cast<bool>(ex2));
    assert(etl::as_const(ex2).has_value());
    assert(static_cast<bool>(etl::as_const(ex2)));
    assert(ex2.value() == T(42));
    assert(etl::as_const(ex2).value() == T(42));
    assert(*ex2 == T(42));
    assert(*etl::as_const(ex2) == T(42));

    auto ex3 = expected_t {etl::unexpect, 143};
    assert(not ex3.has_value());
    assert(not static_cast<bool>(ex3));
    assert(not etl::as_const(ex3).has_value());
    assert(not static_cast<bool>(etl::as_const(ex3)));
    assert(ex3.error() == 143);
    assert(etl::as_const(ex3).error() == 143);
    assert(ex3.value_or(42.0F) == T(42));
    assert(etl::as_const(ex3).value_or(42.0F) == T(42));
    assert(etl::move(ex3).value_or(42.0F) == T(42));

    return true;
}

static auto test_all() -> bool
{
    // E == int
    assert(test<signed char, int>());
    assert(test<signed short, int>());
    // assert(test<signed int, int>());
    assert(test<signed long, int>());
    assert(test<signed long long, int>());

    assert(test<unsigned char, int>());
    assert(test<unsigned short, int>());
    assert(test<unsigned int, int>());
    assert(test<unsigned long, int>());
    assert(test<unsigned long long, int>());

    // E == class
    assert(test<signed char, error_class>());
    assert(test<signed short, error_class>());
    assert(test<signed int, error_class>());
    assert(test<signed long, error_class>());
    assert(test<signed long long, error_class>());

    assert(test<unsigned char, error_class>());
    assert(test<unsigned short, error_class>());
    assert(test<unsigned int, error_class>());
    assert(test<unsigned long, error_class>());
    assert(test<unsigned long long, error_class>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}

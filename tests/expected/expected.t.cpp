// SPDX-License-Identifier: BSL-1.0

#include <etl/expected.hpp>

#include <etl/concepts.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {
struct Error {
    constexpr Error() = default;

    constexpr explicit Error(int v)
        : value(v)
    {
    }

    int value{0};

    friend constexpr auto operator==(Error ec, int v) { return ec.value == v; }
};
} // namespace

template <typename T, typename E>
constexpr auto test() -> bool
{
    using expected_t = etl::expected<T, E>;

    CHECK(etl::is_default_constructible_v<expected_t>);
    CHECK(etl::is_nothrow_default_constructible_v<expected_t>);

    CHECK_SAME_TYPE(typename expected_t::value_type, T);
    CHECK_SAME_TYPE(typename expected_t::error_type, E);
    CHECK_SAME_TYPE(typename expected_t::unexpected_type, etl::unexpected<E>);
    CHECK_SAME_TYPE(typename expected_t::template rebind<float>, etl::expected<float, E>);

    CHECK(noexcept(etl::declval<expected_t>().has_value()));
    CHECK(noexcept(static_cast<bool>(etl::declval<expected_t>())));

    auto ex1 = expected_t{};
    CHECK(ex1.has_value());
    CHECK(static_cast<bool>(ex1));
    CHECK(etl::as_const(ex1).has_value());
    CHECK(static_cast<bool>(etl::as_const(ex1)));
    CHECK(*ex1 == 0);
    CHECK(*etl::as_const(ex1) == 0);
    CHECK(ex1.value_or(42.0F) == 0);
    CHECK(etl::as_const(ex1).value_or(42.0F) == 0);
    CHECK(*expected_t() == 0);

    auto ex2 = expected_t{etl::in_place, T(42)};
    CHECK(ex2.has_value());
    CHECK(static_cast<bool>(ex2));
    CHECK(etl::as_const(ex2).has_value());
    CHECK(static_cast<bool>(etl::as_const(ex2)));
    CHECK(*ex2 == T(42));
    CHECK(*etl::as_const(ex2) == T(42));

    auto ex3 = expected_t{etl::unexpect, 143};
    CHECK_FALSE(ex3.has_value());
    CHECK_FALSE(static_cast<bool>(ex3));
    CHECK_FALSE(etl::as_const(ex3).has_value());
    CHECK_FALSE(static_cast<bool>(etl::as_const(ex3)));
    CHECK(ex3.error() == 143);
    CHECK(etl::as_const(ex3).error() == 143);
    CHECK(ex3.value_or(42.0F) == T(42));
    CHECK(etl::as_const(ex3).value_or(42.0F) == T(42));

    ex3.emplace(T(99));
    CHECK(ex3.has_value());
    CHECK(static_cast<bool>(ex3));
    CHECK(*ex3 == T(99));
    CHECK(*etl::as_const(ex3) == T(99));
    CHECK(ex3.value_or(42.0F) == T(99));
    CHECK(etl::as_const(ex3).value_or(42.0F) == T(99));

    return true;
}

constexpr auto test_all() -> bool
{
    // E == int
    CHECK(test<signed char, int>());
    CHECK(test<signed short, int>());
    CHECK(test<signed int, int>());
    CHECK(test<signed long, int>());
    CHECK(test<signed long long, int>());

    CHECK(test<unsigned char, int>());
    CHECK(test<unsigned short, int>());
    CHECK(test<unsigned int, int>());
    CHECK(test<unsigned long, int>());
    CHECK(test<unsigned long long, int>());

    // E == class
    CHECK(test<signed char, Error>());
    CHECK(test<signed short, Error>());
    CHECK(test<signed int, Error>());
    CHECK(test<signed long, Error>());
    CHECK(test<signed long long, Error>());

    CHECK(test<unsigned char, Error>());
    CHECK(test<unsigned short, Error>());
    CHECK(test<unsigned int, Error>());
    CHECK(test<unsigned long, Error>());
    CHECK(test<unsigned long long, Error>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

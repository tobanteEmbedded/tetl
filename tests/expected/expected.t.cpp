// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/concepts.hpp>
    #include <etl/expected.hpp>
    #include <etl/utility.hpp>
#endif

namespace {
struct Error {
    constexpr Error() = default;

    constexpr explicit Error(int v)
        : value(v)
    {
    }

    int value{0};

    friend constexpr auto operator==(Error ec, int v)
    {
        return ec.value == v;
    }
};
struct MoveOnlyType {
    constexpr MoveOnlyType() = default;

    constexpr MoveOnlyType(MoveOnlyType const& e)                    = delete;
    constexpr auto operator=(MoveOnlyType const& e) -> MoveOnlyType& = delete;

    constexpr MoveOnlyType(MoveOnlyType&& e)                    = default;
    constexpr auto operator=(MoveOnlyType&& e) -> MoveOnlyType& = default;

    constexpr ~MoveOnlyType() = default;
};

} // namespace

template <typename T, typename E>
static constexpr auto test() -> bool
{
    using expected_t = etl::expected<T, E>;

    CHECK(etl::is_trivially_copy_constructible_v<T>);
    CHECK(etl::is_trivially_copy_constructible_v<E>);

    CHECK(etl::is_default_constructible_v<expected_t>);
    CHECK(etl::is_nothrow_default_constructible_v<expected_t>);
    CHECK(etl::is_copy_constructible_v<expected_t>);
    CHECK(etl::is_trivially_copy_constructible_v<expected_t>);
    CHECK(etl::is_nothrow_copy_constructible_v<expected_t>);
    CHECK(etl::is_trivially_move_constructible_v<expected_t>);
    CHECK(etl::is_nothrow_move_constructible_v<expected_t>);

    CHECK(etl::constructible_from<expected_t, etl::in_place_t, T>);
    CHECK(etl::constructible_from<expected_t, expected_t const&>);

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

static constexpr auto test_all() -> bool
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

    CHECK(etl::is_move_constructible_v<MoveOnlyType>);
    CHECK_FALSE(etl::is_copy_constructible_v<MoveOnlyType>);
    CHECK_FALSE(etl::is_copy_constructible_v<etl::expected<int, MoveOnlyType>>);
    CHECK_FALSE(etl::is_copy_constructible_v<etl::expected<MoveOnlyType, int>>);
    CHECK_FALSE(etl::is_copy_constructible_v<etl::expected<MoveOnlyType, MoveOnlyType>>);

    CHECK(etl::is_copy_constructible_v<etl::expected<int, int>>);
    CHECK(etl::is_trivially_copy_constructible_v<etl::expected<int, char const*>>);

    CHECK(etl::is_trivially_copy_constructible_v<Error>);
    CHECK(etl::is_trivially_copy_constructible_v<etl::expected<int, Error>>);

    CHECK(etl::constructible_from<etl::expected<int, MoveOnlyType>, etl::in_place_t, int>);
    CHECK(etl::constructible_from<etl::expected<int, MoveOnlyType>, etl::expected<int, MoveOnlyType>&&>);
    CHECK_FALSE(etl::constructible_from<etl::expected<int, MoveOnlyType>, etl::expected<int, MoveOnlyType> const&>);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

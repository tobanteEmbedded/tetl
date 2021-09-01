/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/optional.hpp"

#include "etl/cstdint.hpp"
#include "etl/warning.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("optional: construct() non_trivial", "[optional]")
{
    struct SNT {
        SNT() = default;
        SNT(SNT const& /*unused*/) { }
        SNT(SNT&& /*unused*/) noexcept { }
        auto operator=(SNT const& /*unused*/) -> SNT& { return *this; }
        auto operator=(SNT&& /*unused*/) noexcept -> SNT& { return *this; }
        ~SNT() { }
    };

    STATIC_REQUIRE_FALSE(etl::is_trivially_destructible_v<SNT>);
    STATIC_REQUIRE_FALSE(etl::is_trivially_move_assignable_v<SNT>);
    STATIC_REQUIRE_FALSE(etl::is_trivially_move_constructible_v<SNT>);

    etl::optional<SNT> opt1 { SNT {} };
    CHECK(opt1.has_value());

    {
        auto opt2 { opt1 };
        CHECK(opt2.has_value());

        auto const opt3 { etl::move(opt2) };
        CHECK(opt3.has_value());

        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
        auto const opt4 { opt3 };
        CHECK(opt4.has_value());
    }
}

TEST_CASE("optional: operator=(optional<U>)", "[optional]")
{
    etl::optional<int> opt1 { 42 };

    etl::optional<long> opt2 {};
    CHECK_FALSE(opt2.has_value());
    opt2 = opt1;
    CHECK(opt2.has_value());
    CHECK(opt2.value() == 42);

    etl::optional<long> opt3 {};
    CHECK_FALSE(opt3.has_value());
    opt3 = etl::move(opt1);
    CHECK(opt3.has_value());
    CHECK(opt3.value() == 42);

    etl::optional<long> opt4 { opt1 };
    CHECK(opt4.has_value());
    CHECK(opt4.value() == 42);

    etl::optional<long> opt5 { etl::move(opt1) };
    CHECK(opt5.has_value());
    CHECK(opt5.value() == 42);
}

TEST_CASE("optional: operator=() non_trivial", "[optional]")
{
    struct S {
        S() = default;
        S(S const& /*s*/) { }          // NOLINT(modernize-use-equals-default)
        S(S&& /*unused*/) noexcept { } // NOLINT(modernize-use-equals-default)
        ~S() { }                       // NOLINT(modernize-use-equals-default)
        auto operator=(S const& /*s*/) -> S& { return *this; }
        auto operator=(S&& /*s*/) noexcept -> S& { return *this; }
    };

    STATIC_REQUIRE_FALSE(etl::is_trivially_destructible_v<S>);
    STATIC_REQUIRE_FALSE(etl::is_trivially_move_assignable_v<S>);
    STATIC_REQUIRE_FALSE(etl::is_trivially_move_constructible_v<S>);

    etl::optional<S> opt1 {};
    CHECK_FALSE(opt1.has_value());

    opt1 = S {};
    CHECK(opt1.has_value());

    {
        auto opt2 = opt1;
        CHECK(opt2.has_value());

        auto const opt3 = etl::move(opt2);
        CHECK(opt3.has_value());

        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
        auto const opt4 = opt3;
        CHECK(opt4.has_value());
    }
}

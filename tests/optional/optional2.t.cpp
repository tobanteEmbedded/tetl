// SPDX-License-Identifier: BSL-1.0

#include <etl/optional.hpp>

#include <etl/cstdint.hpp>
#include <etl/utility.hpp>

#include "testing/exception.hpp"
#include "testing/testing.hpp"

static constexpr auto test_opional_3() -> bool
{
    etl::optional<int> opt1{42};

    etl::optional<long> opt2{};
    CHECK_FALSE(opt2.has_value());
    opt2 = opt1;
    CHECK(opt2.has_value());
    CHECK(*opt2 == 42);

    etl::optional<long> opt3{};
    CHECK_FALSE(opt3.has_value());
    opt3 = etl::move(opt1);
    CHECK(opt3.has_value());
    CHECK(*opt3 == 42);

    etl::optional<long> opt4{opt1};
    CHECK(opt4.has_value());
    CHECK(*opt4 == 42);

    etl::optional<long> opt5;
    opt5 = etl::optional{143};
    CHECK(opt5.has_value());
    CHECK(*opt5 == 143);

    opt5 = etl::move(opt1);
    CHECK(opt5.has_value());
    CHECK(*opt5 == 42);

    opt5 = etl::optional<int>{};
    CHECK_FALSE(opt5.has_value());

    return true;
}

static constexpr auto test_opional_4() -> bool
{
    struct S {
        constexpr S() = default;

        constexpr S(S const& /*s*/) { } // NOLINT(modernize-use-equals-default)

        constexpr S(S&& /*unused*/) noexcept { } // NOLINT(modernize-use-equals-default)

        constexpr ~S() { } // NOLINT(modernize-use-equals-default)

        constexpr auto operator=(S const& /*s*/) -> S& { return *this; }

        constexpr auto operator=(S&& /*s*/) noexcept -> S& { return *this; }
    };

    CHECK_FALSE(etl::is_trivially_destructible_v<S>);
    CHECK_FALSE(etl::is_trivially_move_assignable_v<S>);
    CHECK_FALSE(etl::is_trivially_move_constructible_v<S>);

    etl::optional<S> opt1{};
    CHECK_FALSE(opt1.has_value());

    opt1 = S{};
    CHECK(opt1.has_value());

    {
        auto opt2 = opt1;
        CHECK(opt2.has_value());

        auto opt3 = etl::move(opt2);
        CHECK(opt3.has_value());

        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
        opt1 = opt3;
        CHECK(opt1.has_value());

        opt3 = etl::move(opt1);
        CHECK(opt3.has_value());
    }

    {
        struct SX {
            int data;

            constexpr SX(int c)
                : data{c}
            {
            }

            constexpr ~SX() { }

            constexpr SX(SX const& /*other*/)                        = default;
            constexpr SX(SX&& /*other*/) noexcept                    = default;
            constexpr auto operator=(SX const& /*other*/) -> SX&     = default;
            constexpr auto operator=(SX&& /*other*/) noexcept -> SX& = default;
        };

        etl::optional<SX> l{1};
        etl::optional<SX> r{2};
        CHECK(l.has_value());
        CHECK(r.has_value());

        l.swap(r);
        CHECK(l.has_value());
        CHECK(r.has_value());
        CHECK(l->data == 2);
        CHECK(r->data == 1);
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test_opional_3());
    CHECK(test_opional_4());
    return true;
}

auto main() -> int
{
#if defined(_MSC_VER) and not defined(__clang__)
    CHECK(test_all());
#else
    STATIC_CHECK(test_all());
#endif
    return 0;
}

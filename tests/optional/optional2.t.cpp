// SPDX-License-Identifier: BSL-1.0

#include <etl/optional.hpp>

#include <etl/cstdint.hpp>
#include <etl/warning.hpp>

#include "testing/exception.hpp"
#include "testing/testing.hpp"

static auto test_opional_2() -> bool
{
    struct SNT {
        SNT() = default;

        SNT(SNT const& /*unused*/) { }

        SNT(SNT&& /*unused*/) noexcept { }

        auto operator=(SNT const& /*unused*/) -> SNT& { return *this; }

        auto operator=(SNT&& /*unused*/) noexcept -> SNT& { return *this; }

        ~SNT() { }
    };

    CHECK(!(etl::is_trivially_destructible_v<SNT>));
    CHECK(!(etl::is_trivially_move_assignable_v<SNT>));
    CHECK(!(etl::is_trivially_move_constructible_v<SNT>));

    etl::optional<SNT> opt1{SNT{}};
    CHECK(opt1.has_value());

    {
        auto opt2{opt1};
        CHECK(opt2.has_value());

        auto const opt3{etl::move(opt2)};
        CHECK(opt3.has_value());

        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
        auto const opt4{opt3};
        CHECK(opt4.has_value());
    }

    return true;
}

static auto test_opional_3() -> bool
{
    etl::optional<int> opt1{42};

    etl::optional<long> opt2{};
    CHECK(!(opt2.has_value()));
    opt2 = opt1;
    CHECK(opt2.has_value());
    CHECK(opt2.value() == 42);

    etl::optional<long> opt3{};
    CHECK(!(opt3.has_value()));
    opt3 = etl::move(opt1);
    CHECK(opt3.has_value());
    CHECK(opt3.value() == 42);

    etl::optional<long> opt4{opt1};
    CHECK(opt4.has_value());
    CHECK(opt4.value() == 42);

    etl::optional<long> opt5{etl::move(opt1)};
    CHECK(opt5.has_value());
    CHECK(opt5.value() == 42);

    return true;
}

static auto test_opional_4() -> bool
{
    struct S {
        S() = default;

        S(S const& /*s*/) { } // NOLINT(modernize-use-equals-default)

        S(S&& /*unused*/) noexcept { } // NOLINT(modernize-use-equals-default)

        ~S() { } // NOLINT(modernize-use-equals-default)

        auto operator=(S const& /*s*/) -> S& { return *this; }

        auto operator=(S&& /*s*/) noexcept -> S& { return *this; }
    };

    CHECK(!(etl::is_trivially_destructible_v<S>));
    CHECK(!(etl::is_trivially_move_assignable_v<S>));
    CHECK(!(etl::is_trivially_move_constructible_v<S>));

    etl::optional<S> opt1{};
    CHECK(!(opt1.has_value()));

    opt1 = S{};
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

    {
        struct SX {
            int data;

            SX(int c) : data{c} { }

            ~SX() { }

            SX(SX const& /*other*/)                        = default;
            SX(SX&& /*other*/) noexcept                    = default;
            auto operator=(SX const& /*other*/) -> SX&     = default;
            auto operator=(SX&& /*other*/) noexcept -> SX& = default;
        };

        etl::optional<SX> l{1};
        etl::optional<SX> r{2};
        CHECK((l.has_value()));
        CHECK((r.has_value()));

        l.swap(r);
        CHECK((l.has_value()));
        CHECK((r.has_value()));
        CHECK((l.value().data == 2));
        CHECK((r.value().data == 1));
    }

    return true;
}

static auto test_all() -> bool
{
    CHECK(test_opional_2());
    CHECK(test_opional_3());
    CHECK(test_opional_4());
    return true;
}

auto main() -> int
{
    CHECK(test_all());

    // TODO: [tobi] Add constexpr tests
    // static_assert(test_all());
    return 0;
}

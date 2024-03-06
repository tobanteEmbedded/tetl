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

    assert(!(etl::is_trivially_destructible_v<SNT>));
    assert(!(etl::is_trivially_move_assignable_v<SNT>));
    assert(!(etl::is_trivially_move_constructible_v<SNT>));

    etl::optional<SNT> opt1 {SNT {}};
    assert(opt1.has_value());

    {
        auto opt2 {opt1};
        assert(opt2.has_value());

        auto const opt3 {etl::move(opt2)};
        assert(opt3.has_value());

        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
        auto const opt4 {opt3};
        assert(opt4.has_value());
    }

    return true;
}

static auto test_opional_3() -> bool
{
    etl::optional<int> opt1 {42};

    etl::optional<long> opt2 {};
    assert(!(opt2.has_value()));
    opt2 = opt1;
    assert(opt2.has_value());
    assert(opt2.value() == 42);

    etl::optional<long> opt3 {};
    assert(!(opt3.has_value()));
    opt3 = etl::move(opt1);
    assert(opt3.has_value());
    assert(opt3.value() == 42);

    etl::optional<long> opt4 {opt1};
    assert(opt4.has_value());
    assert(opt4.value() == 42);

    etl::optional<long> opt5 {etl::move(opt1)};
    assert(opt5.has_value());
    assert(opt5.value() == 42);

    return true;
}

static auto test_opional_4() -> bool
{
    struct S {
        S() = default;
        S(S const& /*s*/) { }          // NOLINT(modernize-use-equals-default)
        S(S&& /*unused*/) noexcept { } // NOLINT(modernize-use-equals-default)
        ~S() { }                       // NOLINT(modernize-use-equals-default)
        auto operator=(S const& /*s*/) -> S& { return *this; }
        auto operator=(S&& /*s*/) noexcept -> S& { return *this; }
    };

    assert(!(etl::is_trivially_destructible_v<S>));
    assert(!(etl::is_trivially_move_assignable_v<S>));
    assert(!(etl::is_trivially_move_constructible_v<S>));

    etl::optional<S> opt1 {};
    assert(!(opt1.has_value()));

    opt1 = S {};
    assert(opt1.has_value());

    {
        auto opt2 = opt1;
        assert(opt2.has_value());

        auto const opt3 = etl::move(opt2);
        assert(opt3.has_value());

        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
        auto const opt4 = opt3;
        assert(opt4.has_value());
    }

    {
        struct SX {
            int data;

            SX(int c) : data {c} { }
            ~SX() { }
            SX(SX const& /*other*/)                        = default;
            SX(SX&& /*other*/) noexcept                    = default;
            auto operator=(SX const& /*other*/) -> SX&     = default;
            auto operator=(SX&& /*other*/) noexcept -> SX& = default;
        };

        etl::optional<SX> l {1};
        etl::optional<SX> r {2};
        assert((l.has_value()));
        assert((r.has_value()));

        l.swap(r);
        assert((l.has_value()));
        assert((r.has_value()));
        assert((l.value().data == 2));
        assert((r.value().data == 1));
    }

    return true;
}

static auto test_all() -> bool
{
    assert(test_opional_2());
    assert(test_opional_3());
    assert(test_opional_4());
    return true;
}

auto main() -> int
{
    assert(test_all());

    // TODO: [tobi] Add constexpr tests
    // static_assert(test_all());
    return 0;
}

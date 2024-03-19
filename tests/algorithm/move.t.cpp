// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>

#include "testing/testing.hpp"

template <typename T>
struct S {
    constexpr S(T d = T(0)) : data{d} { }

    constexpr S(S const& s) : data{s.data}, copy{true} { }

    constexpr S(S&& s) noexcept : data{s.data}, move{true} { }

    constexpr auto operator=(S const& s) noexcept -> S&
    {
        data = s.data;
        copy = true;
        return *this;
    }

    constexpr auto operator=(S&& s) noexcept -> S&
    {
        data = s.data;
        move = true;
        return *this;
    }

    T data; // NOLINT
    bool copy = false;
    bool move = false;
};

template <typename T>
constexpr auto test() -> bool
{
    // move forward
    {
        // move

        auto source = etl::array{S(T(1)), S(T(1)), S(T(1))};
        decltype(source) d{};
        etl::move(begin(source), end(source), begin(d));

        // CHECK
        using etl::all_of;

        CHECK((all_of(begin(d), end(d), [](auto const& s) { return s.move; })));
        CHECK((all_of(begin(d), end(d), [](auto const& s) { return !s.copy; })));
        CHECK((all_of(begin(d), end(d), [](auto const& s) { return s.data == 1; })));
    }

    // move backward
    {
        // move
        auto source = etl::array{S(T(1)), S(T(2)), S(T(3))};
        decltype(source) d{};
        etl::move_backward(begin(source), end(source), end(d));

        // CHECK
        using etl::all_of;

        CHECK(all_of(begin(d), end(d), [](auto const& s) { return s.move; }));
        CHECK(all_of(begin(d), end(d), [](auto const& s) { return !s.copy; }));
        CHECK(all_of(begin(d), end(d), [](auto const& s) { return s.data != 0; }));
        CHECK(d[0].data == T(1));
        CHECK(d[1].data == T(2));
        CHECK(d[2].data == T(3));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

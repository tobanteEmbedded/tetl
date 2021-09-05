/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"

#include "testing/testing.hpp"

template <typename T>
struct S {
    S(T d = T(0)) : data { d } { }

    S(S const& s)
    {
        data = s.data;
        copy = true;
    }

    S(S&& s) noexcept
    {
        data = s.data;
        move = true;
    }

    auto operator=(S const& s) noexcept -> S&
    {
        data = s.data;
        copy = true;
        return *this;
    }

    auto operator=(S&& s) noexcept -> S&
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

        auto source = etl::array { S(T(1)), S(T(1)), S(T(1)) };
        decltype(source) d {};
        etl::move(begin(source), end(source), begin(d));

        // assert
        using etl::all_of;

        // clang-format off
        assert((all_of(begin(d), end(d), [](auto const&s) { return s.move; })));
        assert((all_of(begin(d), end(d), [](auto const&s) { return !s.copy; })));
        assert((all_of(begin(d), end(d), [](auto const&s) { return s.data == 1; })));
        // clang-format on
    }

    // move backward
    {
        // move
        auto source = etl::array { S(T(1)), S(T(2)), S(T(3)) };
        decltype(source) d {};
        etl::move_backward(begin(source), end(source), end(d));

        // assert
        using etl::all_of;

        // clang-format off
        assert(all_of(begin(d), end(d), [](auto const&s) { return s.move; }));
        assert(all_of(begin(d), end(d), [](auto const&s) { return !s.copy; }));
        assert(all_of(begin(d), end(d), [](auto const&s) { return s.data != 0; }));
        // clang-format on
        assert(d[0].data == T(1));
        assert(d[1].data == T(2));
        assert(d[2].data == T(3));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    // static_assert(test_all());
    return 0;
}
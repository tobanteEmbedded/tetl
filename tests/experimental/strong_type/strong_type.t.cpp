/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/experimental/strong_type/strong_type.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "testing.hpp"

using namespace etl::experimental;

template <typename T>
constexpr auto test() -> bool
{

    {

        using Kilogram = strong_type<T, struct Kilogram_tag>;
        auto kilo      = Kilogram {};
        kilo           = Kilogram { 0 };

        assert((kilo.raw_value() == T { 0 }));
    }

    {

        using Kilo = strong_type<T, struct Kilo_tag>;

        assert((sizeof(Kilo) == sizeof(typename Kilo::value_type)));

        assert((etl::is_constructible_v<Kilo>));
        assert((etl::is_trivially_constructible_v<Kilo>));
        assert((etl::is_nothrow_constructible_v<Kilo>));

        assert((etl::is_destructible_v<Kilo>));
        assert((etl::is_trivially_destructible_v<Kilo>));
        assert((etl::is_nothrow_destructible_v<Kilo>));

        assert((etl::is_assignable_v<Kilo, Kilo>));
        assert((etl::is_trivially_assignable_v<Kilo, Kilo>));
        assert((etl::is_nothrow_assignable_v<Kilo, Kilo>));

        assert((etl::is_copy_constructible_v<Kilo>));
        assert((etl::is_trivially_copy_constructible_v<Kilo>));
        assert((etl::is_nothrow_copy_constructible_v<Kilo>));

        assert((etl::is_copy_assignable_v<Kilo>));
        assert((etl::is_trivially_copy_assignable_v<Kilo>));
        assert((etl::is_nothrow_copy_assignable_v<Kilo>));

        assert((etl::is_move_constructible_v<Kilo>));
        assert((etl::is_trivially_move_constructible_v<Kilo>));
        assert((etl::is_nothrow_move_constructible_v<Kilo>));

        assert((etl::is_move_assignable_v<Kilo>));
        assert((etl::is_trivially_move_assignable_v<Kilo>));
        assert((etl::is_nothrow_move_assignable_v<Kilo>));

        assert((etl::is_swappable_v<Kilo>));
        assert((etl::is_nothrow_swappable_v<Kilo>));

        assert((!etl::has_virtual_destructor_v<Kilo>));
    }

    {

        using Kilo     = strong_type<T, struct Kilo_tag, skill::addable>;
        auto const lhs = Kilo(1);
        auto const rhs = Kilo(2);
        auto const sum = lhs + rhs;
        assert((sum.raw_value() == T(3)));
    }

    {

        using Kilo     = strong_type<T, struct Kilo_tag, skill::subtractable>;
        auto const lhs = Kilo(2);
        auto const rhs = Kilo(1);
        auto const sum = lhs - rhs;
        assert((sum.raw_value() == T(1)));
    }

    {

        using Kilo     = strong_type<T, struct Kilo_tag, skill::multipliable>;
        auto const lhs = Kilo(2);
        auto const rhs = Kilo(2);
        auto const sum = lhs * rhs;
        assert((sum.raw_value() == T(4)));
    }

    {

        using Kilo     = strong_type<T, struct Kilo_tag, skill::divisible>;
        auto const lhs = Kilo(2);
        auto const rhs = Kilo(2);
        auto const sum = lhs / rhs;
        assert((sum.raw_value() == T(1)));
    }

    {

        using Hertz    = strong_type<T, struct Hertz_tag, skill::comparable>;
        auto const lhs = Hertz { typename Hertz::value_type(44) };
        auto const rhs = Hertz { typename Hertz::value_type(48) };

        assert((lhs.raw_value() == typename Hertz::value_type(44)));
        assert((rhs.raw_value() == typename Hertz::value_type(48)));

        assert((lhs < rhs));
        assert((!(lhs > rhs)));

        assert((lhs <= rhs));
        assert((!(lhs >= rhs)));

        assert((lhs != rhs));
        assert((!(lhs == rhs)));
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
    assert(test<long double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
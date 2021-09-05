/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/array.hpp"

#include "etl/algorithm.hpp"
#include "etl/cstdint.hpp"
#include "etl/numeric.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test_builtin_types() -> bool
{
    {
        etl::array<T, 2> a {};
        assert(a.empty() == false);
        assert(a.size() == 2);
        assert(a.max_size() == 2);
        assert(a[0] == T { 0 });
        assert(a[1] == T { 0 });
    }

    {
        auto const x = T { 10 };
        auto a       = etl::array { T { 1 }, T { 2 }, x };
        assert(a.size() == 3);
        assert(a.max_size() == 3);

        assert(a.front() == T { 1 });
        assert(a.back() == x);
        assert(a.at(0) == T { 1 });
        assert(a.at(1) == T { 2 });
        assert(a.at(2) == x);
        assert(a[0] == T { 1 });
        assert(a[1] == T { 2 });
        assert(a[2] == x);

        auto const& ac = a;
        assert(ac.front() == T { 1 });
        assert(ac.back() == x);
        assert(ac.at(0) == T { 1 });
        assert(ac.at(1) == T { 2 });
        assert(ac.at(2) == x);
        assert(ac[0] == T { 1 });
        assert(ac[1] == T { 2 });
        assert(ac[2] == x);
    }

    {
        etl::array<T, 4> arr {};
        etl::iota(etl::begin(arr), etl::end(arr), T { 0 });

        assert(*arr.data() == T(0));
        assert(arr.front() == T(0));
        assert(arr.back() == T(3));

        auto counter = 0;
        for (auto& x : arr) {
            assert(x == static_cast<T>(counter));
            ++counter;
        }

        counter = 0;
        for (auto const x : etl::as_const(arr)) {
            assert(x == static_cast<T>(counter));
            ++counter;
        }
    }

    {
        // swap
        using etl::all_of;

        etl::array<T, 4> a {};
        a.fill(T { 1 });
        etl::array<T, 4> b {};

        assert(all_of(begin(a), end(a), [](auto val) { return val == 1; }));
        assert(all_of(begin(b), end(b), [](auto val) { return val == 0; }));

        a.swap(b);
        assert(all_of(begin(a), end(a), [](auto val) { return val == 0; }));
        assert(all_of(begin(b), end(b), [](auto val) { return val == 1; }));

        etl::swap(a, b);
        assert(all_of(begin(a), end(a), [](auto val) { return val == 1; }));
        assert(all_of(begin(b), end(b), [](auto val) { return val == 0; }));
    }

    {
        // TODO: [tobi] Fails in a static_assertion
        // gcc: error: ‘it.etl::reverse_iterator<unsigned char*>::operator*()’
        // is not a constant expression
        // auto arr = etl::array { T(1), T(2), T(3) };
        // auto it  = arr.rbegin();

        // assert(*it == T(3));
        // ++it;
        // assert(*it == T(2));
        // it++;
        // assert(*it == T(1));
    }

    { // not eqaul
        etl::array<T, 3> lhs { T { 1 }, T { 2 }, T { 3 } };
        etl::array<T, 3> rhs { T { 7 }, T { 8 }, T { 9 } };

        assert(!(lhs == rhs));
        assert(lhs != rhs);
        assert(lhs < rhs);
        assert(lhs <= rhs);
        assert(!(lhs > rhs));
        assert(!(lhs >= rhs));
    }

    {
        // eqaul
        etl::array<T, 3> lhs { T { 1 }, T { 2 }, T { 3 } };
        etl::array<T, 3> rhs { T { 1 }, T { 2 }, T { 3 } };

        assert(lhs == rhs);
        assert(!(lhs != rhs));
        assert(!(lhs < rhs));
        assert(lhs <= rhs);
        assert(!(lhs > rhs));
        assert(lhs >= rhs);
    }

    {
        // tuple_size
        assert((etl::tuple_size<etl::array<T, 1>>::value == 1));

        assert((etl::tuple_size_v<etl::array<T, 2>> == 2));
        assert((etl::tuple_size_v<etl::array<T, 3>> == 3));

        auto arr4 = etl::array { T(1), T(2), T(3), T(4) };
        assert(etl::tuple_size_v<decltype(arr4)> == 4);

        auto arr5 = etl::array { 1, 2, 3, 4, 5 };
        assert(etl::tuple_size_v<decltype(arr5)> == 5);
    }

    {
        assert((etl::is_same_v<
            typename etl::tuple_element<1, etl::array<T, 2>>::type, T>));
    }

    {
        // get
        auto a = etl::array<T, 3> {};

        etl::get<0>(a) = T { 1 };
        etl::get<1>(a) = T { 2 };
        etl::get<2>(a) = T { 3 };

        assert(etl::get<0>(a) == T { 1 });
        assert(etl::get<1>(a) == T { 2 });
        assert(etl::get<2>(a) == T { 3 });
    }
    {
        // to_array

        // copies a string literal
        auto a1 = etl::to_array("foo");
        assert(a1.size() == 4);

        // deduces both element type and length
        auto a2 = etl::to_array({ 0, 2, 1, 3 });
        assert((etl::is_same_v<decltype(a2), etl::array<int, 4>>));

        // deduces length with element type specified
        // implicit conversion happens
        auto a3 = etl::to_array<T>({ 0, 1, 3 });
        assert((etl::is_same_v<decltype(a3), etl::array<T, 3>>));

        auto a4 = etl::to_array<etl::pair<T, float>>({
            { T { 3 }, 0.0F },
            { T { 4 }, 0.1F },
            { T { 4 }, 0.1e23F },
        });
        assert(a4.size() == 3);

        struct non_copy {
            T val;

            constexpr non_copy(T init) : val { init } { }
            non_copy(non_copy&&) noexcept = default;
            non_copy(non_copy const&)     = delete;
            auto operator=(non_copy&&) noexcept -> non_copy& = default;
            auto operator=(non_copy const&) -> non_copy& = delete;
        };

        // creates a non-copyable etl::array
        auto a5 = etl::to_array({ non_copy(T { 42 }) });
        assert(a5.size() == 1);

        // error: copying multidimensional arrays is not supported
        //    char s[2][6] = {"nice", "thing"};
        //    auto a6      = etl::to_array(s);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_builtin_types<etl::uint8_t>());
    assert(test_builtin_types<etl::int8_t>());
    assert(test_builtin_types<etl::uint16_t>());
    assert(test_builtin_types<etl::int16_t>());
    assert(test_builtin_types<etl::uint32_t>());
    assert(test_builtin_types<etl::int32_t>());
    assert(test_builtin_types<etl::uint64_t>());
    assert(test_builtin_types<etl::int64_t>());
    assert(test_builtin_types<float>());
    assert(test_builtin_types<double>());
    assert(test_builtin_types<long double>());
    return true;
}

auto main() -> int
{
    static_assert(test_all());
    assert(test_all());
    return 0;
}
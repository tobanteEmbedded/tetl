// SPDX-License-Identifier: BSL-1.0

#include "etl/utility.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"
#include "etl/warning.hpp"

#include "testing/testing.hpp"

namespace {
struct DummyString;
struct DummyStringView {
    constexpr DummyStringView() = default;
    constexpr DummyStringView(DummyString const& /*ignore*/);
};
struct DummyString {
    constexpr DummyString() = default;
    constexpr explicit DummyString(DummyStringView /*ignore*/) { }
    constexpr operator DummyStringView() const noexcept { return { *this }; }
};
constexpr DummyStringView::DummyStringView(DummyString const& /*ignore*/) { }

} // namespace

template <typename T>
constexpr auto test() -> bool
{
    // explicit ctors
    etl::ignore_unused(etl::pair<T, DummyString>(T(0), DummyStringView()));
    etl::ignore_unused(etl::pair<T, DummyString>(T(0), DummyString()));
    etl::ignore_unused(etl::pair<T, DummyStringView>(T(0), DummyStringView()));
    etl::ignore_unused(etl::pair<T, DummyStringView>(T(0), DummyStringView()));

    using etl::is_same_v;

    // mutable
    {
        auto p = etl::pair<T, int> {};
        assert((is_same_v<T, decltype(p.first)>));
        assert((is_same_v<int, decltype(p.second)>));
        assert(p.first == T {});
        assert(p.second == int {});
        assert(etl::as_const(p).first == T {});
        assert(etl::as_const(p).second == int {});
    }

    // same type twice
    {
        auto p = etl::pair<T, T> {};
        assert((is_same_v<T, decltype(p.first)>));
        assert((is_same_v<T, decltype(p.second)>));
        assert(p.first == T {});
        assert(p.second == T {});
    }

    {
        auto p1 = etl::pair { T { 0 }, 143.0F };
        assert((is_same_v<T, decltype(p1.first)>));
        assert((is_same_v<float, decltype(p1.second)>));
        assert(p1.first == 0);
        assert(p1.second == 143.0);

        auto p2 = etl::pair { 1.2, T { 42 } };
        assert((is_same_v<double, decltype(p2.first)>));
        assert((is_same_v<T, decltype(p2.second)>));
        assert(p2.first == 1.2);
        assert(p2.second == T { 42 });

        auto p3 = etl::pair { T { 2 }, T { 42 } };
        assert((is_same_v<T, decltype(p3.first)>));
        assert((is_same_v<T, decltype(p3.second)>));
        assert(p3.first == T { 2 });
        assert(p3.second == T { 42 });
    }

    // same types
    {
        auto p = etl::make_pair(T { 0 }, 143.0F);
        auto other { p };

        assert((is_same_v<decltype(other.first), decltype(p.first)>));
        assert((is_same_v<decltype(other.second), decltype(p.second)>));

        assert(other.first == p.first);
        assert(other.second == p.second);
    }

    // different types
    {
        auto p     = etl::make_pair(T { 0 }, 143.0F);
        auto other = etl::pair<T, double> { p };

        assert((is_same_v<decltype(other.first), decltype(p.first)>));
        assert(!(is_same_v<decltype(other.second), decltype(p.second)>));

        assert(other.first == p.first);
        assert(other.second == p.second);
    }

    // same types
    {
        auto p = etl::make_pair(T { 0 }, 143.0F);
        auto other { etl::move(p) };

        assert((is_same_v<decltype(other.first), decltype(p.first)>));
        assert((is_same_v<decltype(other.second), decltype(p.second)>));

        assert(other.first == p.first);
        assert(other.second == p.second);
    }

    // different types
    {
        auto p     = etl::make_pair(T { 0 }, 143.0F);
        auto other = etl::pair<T, double> { etl::move(p) };

        assert((is_same_v<decltype(other.first), decltype(p.first)>));
        assert(!(is_same_v<decltype(other.second), decltype(p.second)>));

        assert(other.first == p.first);
        assert(other.second == p.second);
    }

    // same types
    {
        auto p     = etl::make_pair(T { 0 }, 143.0F);
        auto other = etl::pair<T, float> {};
        other      = p;
        assert(other.first == p.first);
        assert(other.second == p.second);
    }
    // different types
    {
        auto p     = etl::make_pair(T { 0 }, 143.0F);
        auto other = etl::pair<T, double> {};
        other      = p;

        assert((is_same_v<decltype(other.first), decltype(p.first)>));
        assert(!(is_same_v<decltype(other.second), decltype(p.second)>));

        assert(other.first == p.first);
        assert(other.second == static_cast<float>(p.second));
    }

    // same types
    {
        auto p     = etl::make_pair(T { 0 }, 143.0F);
        auto other = etl::pair<T, float> {};
        other      = etl::move(p);
        assert(other.first == p.first);
        assert(other.second == p.second);
    }
    // different types
    {
        auto other = etl::pair<T, double> {};
        auto p     = etl::make_pair(T { 0 }, 143.0F);
        other      = etl::move(p);

        assert((is_same_v<decltype(other.first), decltype(p.first)>));
        assert(!(is_same_v<decltype(other.second), decltype(p.second)>));

        assert(other.first == p.first);
        assert(other.second == static_cast<float>(p.second));
    }

    {
        T a[2] {};
        T b[3] {};
        etl::pair p { a, b }; // explicit deduction guide is used in this case

        assert((is_same_v<T*, decltype(p.first)>));
        assert((is_same_v<T*, decltype(p.second)>));
    }

    {
        auto p = etl::make_pair(T { 0 }, 143.0F);
        assert((is_same_v<T, decltype(p.first)>));
        assert((is_same_v<float, decltype(p.second)>));

        assert(p.first == 0);
        assert(p.second == 143.0);
    }

    using pair_type = etl::pair<T, int>;
    using etl::swap;

    // empty
    {
        auto lhs = pair_type();
        auto rhs = pair_type();
        assert(lhs.first == T());
        assert(lhs == rhs);

        swap(lhs, rhs);
        assert(lhs.first == T());
        assert(lhs == rhs);
    }

    // not empty
    {
        auto lhs = pair_type();
        auto rhs = pair_type(T(42), 143);
        assert(lhs.first == T());

        swap(lhs, rhs);
        assert(lhs.first == T(42));
        assert(lhs.second == 143);

        swap(lhs, rhs);
        assert(rhs.first == T(42));
        assert(rhs.second == 143);
    }
    {
        auto const p1 = etl::make_pair(T { 42 }, 143.0F);
        auto const p2 = etl::make_pair(T { 42 }, 143.0F);
        auto const p3 = etl::make_pair(T { 123 }, 143.0F);

        assert(p1 == p2);
        assert(p2 == p1);

        assert(!(p3 == p2));
        assert(!(p3 == p1));
    }

    {
        auto const p1 = etl::make_pair(T { 42 }, 143.0F);
        auto const p2 = etl::make_pair(T { 42 }, 143.0F);
        auto const p3 = etl::make_pair(T { 123 }, 143.0F);

        assert(!(p1 != p2));
        assert(!(p2 != p1));

        assert(p3 != p2);
        assert(p3 != p1);
    }

    {
        auto const p1 = etl::make_pair(T { 42 }, 143.0F);
        auto const p2 = etl::make_pair(T { 42 }, 143.0F);
        auto const p3 = etl::make_pair(T { 123 }, 143.0F);

        assert(!(p1 < p2));
        assert(!(p2 < p1));

        assert(p2 < p3);
        assert(p1 < p3);
    }

    {
        auto const p1 = etl::make_pair(T { 42 }, 143.0F);
        auto const p2 = etl::make_pair(T { 42 }, 143.0F);
        auto const p3 = etl::make_pair(T { 123 }, 143.0F);

        assert(p1 <= p2);
        assert(p2 <= p1);

        assert(p2 <= p3);
        assert(p1 <= p3);
    }

    {
        auto const p1 = etl::make_pair(T { 42 }, 143.0F);
        auto const p2 = etl::make_pair(T { 24 }, 143.0F);
        auto const p3 = etl::make_pair(T { 123 }, 143.0F);

        assert(p1 > p2);
        assert(!(p2 > p1));

        assert(!(p2 > p3));
        assert(!(p1 > p3));
    }

    {
        auto const p1 = etl::make_pair(T { 42 }, 143.0F);
        auto const p2 = etl::make_pair(T { 24 }, 143.0F);
        auto const p3 = etl::make_pair(T { 123 }, 143.0F);

        assert(p1 >= p2);
        assert(!(p2 >= p1));

        assert(!(p2 >= p3));
        assert(!(p1 >= p3));
    }

    {
        assert((etl::tuple_size<etl::pair<T, T>>::value == 2));
        assert((etl::tuple_size_v<etl::pair<T, T>> == 2));

        assert((etl::tuple_size<etl::pair<T, float>>::value == 2));
        assert((etl::tuple_size_v<etl::pair<T, float>> == 2));

        assert((etl::tuple_size<etl::pair<float, T>>::value == 2));
        assert((etl::tuple_size_v<etl::pair<float, T>> == 2));
    }

    {
        using etl::tuple_element_t;
        auto p = etl::pair<T, float> { T { 42 }, 143.0F };
        assert((is_same_v<T, tuple_element_t<0, decltype(p)>>));
        assert((is_same_v<float, tuple_element_t<1, decltype(p)>>));
    }

    {
        using etl::pair;

        // mutable lvalue ref
        {
            auto p = pair<T, float> { T { 42 }, 143.0F };

            auto& first = etl::get<0>(p);
            assert((is_same_v<decltype(first), T&>));
            assert(first == T { 42 });

            auto& second = etl::get<1>(p);
            assert((is_same_v<decltype(second), float&>));
            assert(second == 143.0F);
        }

        // const lvalue ref
        {
            auto const p = pair<T, float> { T { 42 }, 143.0F };

            auto& first = etl::get<0>(p);
            assert((is_same_v<decltype(first), T const&>));
            assert(first == T { 42 });

            auto& second = etl::get<1>(p);
            assert((is_same_v<decltype(second), float const&>));
            assert(second == 143.0F);
        }

        // mutable rvalue ref
        {
            assert((is_same_v<decltype(etl::get<0>(pair { T { 42 }, 143.0F })), T&&>));
            assert((is_same_v<decltype(etl::get<1>(pair { T { 42 }, 143.0F })), float&&>));
        }
    }

    {
        using etl::is_same_v;

        auto seq0 = etl::make_integer_sequence<T, 0> {};
        assert((is_same_v<T, typename decltype(seq0)::value_type>));
        assert((seq0.size() == 0));

        auto seq1 = etl::make_integer_sequence<T, 1> {};
        assert((is_same_v<T, typename decltype(seq1)::value_type>));
        assert((seq1.size() == 1));

        auto seq2 = etl::make_integer_sequence<T, 2> {};
        assert((is_same_v<T, typename decltype(seq2)::value_type>));
        assert((seq2.size() == 2));

        auto seqI = etl::make_index_sequence<10> {};
        assert((is_same_v<etl::size_t, typename decltype(seqI)::value_type>));
        assert((seqI.size() == 10));
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
    // assert(test<float>());
    // assert(test<double>());
    // assert(test<long double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}

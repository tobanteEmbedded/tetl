// SPDX-License-Identifier: BSL-1.0

#include <etl/utility.hpp>

#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>
#include <etl/warning.hpp>

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

    constexpr operator DummyStringView() const noexcept { return {*this}; }
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
        auto p = etl::pair<T, int>{};
        CHECK(is_same_v<T, decltype(p.first)>);
        CHECK(is_same_v<int, decltype(p.second)>);
        CHECK(p.first == T{});
        CHECK(p.second == int{});
        CHECK(etl::as_const(p).first == T{});
        CHECK(etl::as_const(p).second == int{});
    }

    // same type twice
    {
        auto p = etl::pair<T, T>{};
        CHECK(is_same_v<T, decltype(p.first)>);
        CHECK(is_same_v<T, decltype(p.second)>);
        CHECK(p.first == T{});
        CHECK(p.second == T{});
    }

    {
        auto p1 = etl::pair{T{0}, 143.0F};
        CHECK(is_same_v<T, decltype(p1.first)>);
        CHECK(is_same_v<float, decltype(p1.second)>);
        CHECK(p1.first == 0);
        CHECK(p1.second == 143.0);

        auto p2 = etl::pair{1.2, T{42}};
        CHECK(is_same_v<double, decltype(p2.first)>);
        CHECK(is_same_v<T, decltype(p2.second)>);
        CHECK(p2.first == 1.2);
        CHECK(p2.second == T{42});

        auto p3 = etl::pair{T{2}, T{42}};
        CHECK(is_same_v<T, decltype(p3.first)>);
        CHECK(is_same_v<T, decltype(p3.second)>);
        CHECK(p3.first == T{2});
        CHECK(p3.second == T{42});
    }

    // same types
    {
        auto p = etl::make_pair(T{0}, 143.0F);
        auto other{p};

        CHECK(is_same_v<decltype(other.first), decltype(p.first)>);
        CHECK(is_same_v<decltype(other.second), decltype(p.second)>);

        CHECK(other.first == p.first);
        CHECK(other.second == p.second);
    }

    // different types
    {
        auto p     = etl::make_pair(T{0}, 143.0F);
        auto other = etl::pair<T, double>{p};

        CHECK(is_same_v<decltype(other.first), decltype(p.first)>);
        CHECK(!(is_same_v<decltype(other.second), decltype(p.second)>));

        CHECK(other.first == p.first);
        CHECK(other.second == p.second);
    }

    // same types
    {
        auto p = etl::make_pair(T{0}, 143.0F);
        auto other{etl::move(p)};

        CHECK(is_same_v<decltype(other.first), decltype(p.first)>);
        CHECK(is_same_v<decltype(other.second), decltype(p.second)>);

        CHECK(other.first == p.first);
        CHECK(other.second == p.second);
    }

    // different types
    {
        auto p     = etl::make_pair(T{0}, 143.0F);
        auto other = etl::pair<T, double>{etl::move(p)};

        CHECK(is_same_v<decltype(other.first), decltype(p.first)>);
        CHECK(!(is_same_v<decltype(other.second), decltype(p.second)>));

        CHECK(other.first == p.first);
        CHECK(other.second == p.second);
    }

    // same types
    {
        auto p     = etl::make_pair(T{0}, 143.0F);
        auto other = etl::pair<T, float>{};
        other      = p;
        CHECK(other.first == p.first);
        CHECK(other.second == p.second);
    }
    // different types
    {
        auto p     = etl::make_pair(T{0}, 143.0F);
        auto other = etl::pair<T, double>{};
        other      = p;

        CHECK(is_same_v<decltype(other.first), decltype(p.first)>);
        CHECK(!(is_same_v<decltype(other.second), decltype(p.second)>));

        CHECK(other.first == p.first);
        CHECK(other.second == static_cast<float>(p.second));
    }

    // same types
    {
        auto p     = etl::make_pair(T{0}, 143.0F);
        auto other = etl::pair<T, float>{};
        other      = etl::move(p);
        CHECK(other.first == p.first);
        CHECK(other.second == p.second);
    }
    // different types
    {
        auto other = etl::pair<T, double>{};
        auto p     = etl::make_pair(T{0}, 143.0F);
        other      = etl::move(p);

        CHECK(is_same_v<decltype(other.first), decltype(p.first)>);
        CHECK(!(is_same_v<decltype(other.second), decltype(p.second)>));

        CHECK(other.first == p.first);
        CHECK(other.second == static_cast<float>(p.second));
    }

    {
        T a[2]{};
        T b[3]{};
        etl::pair p{a, b}; // explicit deduction guide is used in this case

        CHECK(is_same_v<T*, decltype(p.first)>);
        CHECK(is_same_v<T*, decltype(p.second)>);
    }

    {
        auto p = etl::make_pair(T{0}, 143.0F);
        CHECK(is_same_v<T, decltype(p.first)>);
        CHECK(is_same_v<float, decltype(p.second)>);

        CHECK(p.first == 0);
        CHECK(p.second == 143.0);
    }

    using pair_type = etl::pair<T, int>;
    using etl::swap;

    // empty
    {
        auto lhs = pair_type();
        auto rhs = pair_type();
        CHECK(lhs.first == T());
        CHECK(lhs == rhs);

        swap(lhs, rhs);
        CHECK(lhs.first == T());
        CHECK(lhs == rhs);
    }

    // not empty
    {
        auto lhs = pair_type();
        auto rhs = pair_type(T(42), 143);
        CHECK(lhs.first == T());

        swap(lhs, rhs);
        CHECK(lhs.first == T(42));
        CHECK(lhs.second == 143);

        swap(lhs, rhs);
        CHECK(rhs.first == T(42));
        CHECK(rhs.second == 143);
    }
    {
        auto const p1 = etl::make_pair(T{42}, 143.0F);
        auto const p2 = etl::make_pair(T{42}, 143.0F);
        auto const p3 = etl::make_pair(T{123}, 143.0F);

        CHECK(p1 == p2);
        CHECK(p2 == p1);

        CHECK(!(p3 == p2));
        CHECK(!(p3 == p1));
    }

    {
        auto const p1 = etl::make_pair(T{42}, 143.0F);
        auto const p2 = etl::make_pair(T{42}, 143.0F);
        auto const p3 = etl::make_pair(T{123}, 143.0F);

        CHECK(!(p1 != p2));
        CHECK(!(p2 != p1));

        CHECK(p3 != p2);
        CHECK(p3 != p1);
    }

    {
        auto const p1 = etl::make_pair(T{42}, 143.0F);
        auto const p2 = etl::make_pair(T{42}, 143.0F);
        auto const p3 = etl::make_pair(T{123}, 143.0F);

        CHECK(!(p1 < p2));
        CHECK(!(p2 < p1));

        CHECK(p2 < p3);
        CHECK(p1 < p3);
    }

    {
        auto const p1 = etl::make_pair(T{42}, 143.0F);
        auto const p2 = etl::make_pair(T{42}, 143.0F);
        auto const p3 = etl::make_pair(T{123}, 143.0F);

        CHECK(p1 <= p2);
        CHECK(p2 <= p1);

        CHECK(p2 <= p3);
        CHECK(p1 <= p3);
    }

    {
        auto const p1 = etl::make_pair(T{42}, 143.0F);
        auto const p2 = etl::make_pair(T{24}, 143.0F);
        auto const p3 = etl::make_pair(T{123}, 143.0F);

        CHECK(p1 > p2);
        CHECK(!(p2 > p1));

        CHECK(!(p2 > p3));
        CHECK(!(p1 > p3));
    }

    {
        auto const p1 = etl::make_pair(T{42}, 143.0F);
        auto const p2 = etl::make_pair(T{24}, 143.0F);
        auto const p3 = etl::make_pair(T{123}, 143.0F);

        CHECK(p1 >= p2);
        CHECK(!(p2 >= p1));

        CHECK(!(p2 >= p3));
        CHECK(!(p1 >= p3));
    }

    {
        CHECK(etl::tuple_size<etl::pair<T, T>>::value == 2);
        CHECK(etl::tuple_size_v<etl::pair<T, T>> == 2);

        CHECK(etl::tuple_size<etl::pair<T, float>>::value == 2);
        CHECK(etl::tuple_size_v<etl::pair<T, float>> == 2);

        CHECK(etl::tuple_size<etl::pair<float, T>>::value == 2);
        CHECK(etl::tuple_size_v<etl::pair<float, T>> == 2);
    }

    {
        using etl::tuple_element_t;
        auto p = etl::pair<T, float>{T{42}, 143.0F};
        CHECK(is_same_v<T, tuple_element_t<0, decltype(p)>>);
        CHECK(is_same_v<float, tuple_element_t<1, decltype(p)>>);
    }

    {
        using etl::pair;

        // mutable lvalue ref
        {
            auto p = pair<T, float>{T{42}, 143.0F};

            auto& first = etl::get<0>(p);
            CHECK(is_same_v<decltype(first), T&>);
            CHECK(first == T{42});

            auto& second = etl::get<1>(p);
            CHECK(is_same_v<decltype(second), float&>);
            CHECK(second == 143.0F);
        }

        // const lvalue ref
        {
            auto const p = pair<T, float>{T{42}, 143.0F};

            auto& first = etl::get<0>(p);
            CHECK(is_same_v<decltype(first), T const&>);
            CHECK(first == T{42});

            auto& second = etl::get<1>(p);
            CHECK(is_same_v<decltype(second), float const&>);
            CHECK(second == 143.0F);
        }

        // mutable rvalue ref
        {
            CHECK(is_same_v<decltype(etl::get<0>(pair{T{42}, 143.0F})), T&&>);
            CHECK(is_same_v<decltype(etl::get<1>(pair{T{42}, 143.0F})), float&&>);
        }
    }

    {
        using etl::is_same_v;

        auto seq0 = etl::make_integer_sequence<T, 0>{};
        CHECK(is_same_v<T, typename decltype(seq0)::value_type>);
        CHECK(seq0.size() == 0);

        auto seq1 = etl::make_integer_sequence<T, 1>{};
        CHECK(is_same_v<T, typename decltype(seq1)::value_type>);
        CHECK(seq1.size() == 1);

        auto seq2 = etl::make_integer_sequence<T, 2>{};
        CHECK(is_same_v<T, typename decltype(seq2)::value_type>);
        CHECK(seq2.size() == 2);

        auto seqIdx = etl::make_index_sequence<10>{};
        CHECK(is_same_v<etl::size_t, typename decltype(seqIdx)::value_type>);
        CHECK(seqIdx.size() == 10);
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
    // CHECK(test<float>());
    // CHECK(test<double>());
    // CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

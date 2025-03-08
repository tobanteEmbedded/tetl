// SPDX-License-Identifier: BSL-1.0

#include <etl/span.hpp>

#include <etl/algorithm.hpp>
#include <etl/iterator.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    // empty static
    {
        auto sp = etl::span<T, 0>{};
        CHECK(sp.begin() == nullptr);
        CHECK(sp.begin() == sp.end());
        CHECK(etl::begin(sp) == etl::end(sp));
        CHECK(sp.size() == 0);
    }

    // empty dynamic
    {
        auto sp = etl::span<T>{};
        CHECK(sp.begin() == nullptr);
        CHECK(sp.begin() == sp.end());
        CHECK(etl::begin(sp) == etl::end(sp));
        CHECK(sp.size() == 0);
    }

    // from C array
    {
        T arr[16] = {};
        auto sp   = etl::span{arr};
        CHECK(sp.data() == &arr[0]);
        CHECK(sp.size() == 16);
    }

    // from etl::array
    {
        auto arr = etl::array<T, 8>{};
        auto sp  = etl::span{arr};
        CHECK(sp.data() == arr.data());
        CHECK(sp.size() == 8);
    }

    // from etl::array const
    {
        auto const arr = etl::array<T, 8>{};
        auto const sp  = etl::span{arr};
        CHECK(sp.data() == arr.data());
        CHECK(sp.size() == 8);
    }

    // from Container
    {
        auto vec = etl::static_vector<T, 8>{};
        vec.push_back(T{});
        vec.push_back(T{});
        auto sp = etl::span{vec};
        CHECK(sp.data() == vec.data());
        CHECK(sp.size() == 2);
    }

    // from Container const
    {
        auto const vec = []() {
            auto v = etl::static_vector<T, 8>{};
            v.push_back(T{});
            v.push_back(T{});
            return v;
        }();

        auto const sp = etl::span{vec};
        CHECK(sp.data() == vec.data());
        CHECK(sp.size() == 2);
    }

    {
        auto sp = etl::span<char>{};
        CHECK(sp.data() == nullptr);
        CHECK(sp.size() == 0);
        CHECK(sp.empty());
    }

    // static extent
    {
        auto arr = etl::array<T, 8>{};
        auto sp  = etl::span<T, 8>{etl::begin(arr), etl::size(arr)};
        CHECK_FALSE(sp.empty());
        CHECK(sp.data() == arr.data());
        CHECK(sp.size() == arr.size());
        CHECK(sp.extent == arr.size());
    }

    // static array
    {
        auto arr = etl::array<T, 8>{};
        auto sp  = etl::span<T>{etl::begin(arr), etl::size(arr)};
        CHECK_FALSE(sp.empty());
        CHECK(sp.data() == arr.data());
        CHECK(sp.size() == arr.size());
        CHECK(sp.extent == etl::dynamic_extent);
    }

    // static vector
    {
        auto vec = etl::static_vector<T, 8>{};
        auto rng = []() { return T{42}; };
        etl::generate_n(etl::back_inserter(vec), 4, rng);

        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};
        CHECK_FALSE(sp.empty());
        CHECK(sp.data() == vec.data());
        CHECK(sp.size() == vec.size());
        CHECK(sp.extent == etl::dynamic_extent);
        CHECK(etl::all_of(etl::begin(sp), etl::end(sp), [](auto& x) { return x == T{42}; }));
    }

    // span<U, OtherExtent>
    {
        using static_span        = etl::span<T, 8>;
        using const_static_span  = etl::span<T, 8>;
        using dynamic_span       = etl::span<T>;
        using const_dynamic_span = etl::span<T const>;

        auto buffer = etl::array<T, 8>{};

        dynamic_span dyn = static_span{buffer};
        CHECK(dyn.data() == buffer.data());
        CHECK(dyn.size() == buffer.size());

        const_dynamic_span cdyn = static_span{buffer};
        CHECK(cdyn.data() == buffer.data());
        CHECK(cdyn.size() == buffer.size());

        auto ss = static_span(dynamic_span{buffer});
        CHECK(ss.data() == buffer.data());
        CHECK(ss.size() == buffer.size());

        auto css = const_static_span(dynamic_span{buffer});
        CHECK(css.data() == buffer.data());
        CHECK(css.size() == buffer.size());
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

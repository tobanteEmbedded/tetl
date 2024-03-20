// SPDX-License-Identifier: BSL-1.0

#include <etl/span.hpp>

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        // P2251R1
        CHECK(etl::is_trivially_copyable_v<etl::span<T>>);
        CHECK(etl::is_trivially_copyable_v<etl::span<T const>>);
        CHECK(etl::is_trivially_copyable_v<etl::span<T, 16>>);
        CHECK(etl::is_trivially_copyable_v<etl::span<T const, 16>>);
    }

    // deduction guides
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

    // empty
    {
        auto sp = etl::span<T>{};
        CHECK(sp.begin() == sp.end());
        CHECK(etl::begin(sp) == etl::end(sp));
        CHECK(sp.size() == 0);
    }

    // ranged-for
    {
        auto data = etl::array<T, 4>{};
        auto sp   = etl::span<T>{etl::begin(data), etl::size(data)};
        CHECK_FALSE(sp.begin() == sp.end());
        CHECK_FALSE(etl::begin(sp) == etl::end(sp));

        auto counter = 0;
        for (auto const& x : sp) {
            etl::ignore_unused(x);
            counter++;
        }
        CHECK(counter == 4);
    }

    // algorithm
    {
        auto data = etl::array<T, 4>{};
        auto sp   = etl::span<T>{etl::begin(data), etl::size(data)};
        CHECK_FALSE(sp.begin() == sp.end());
        CHECK_FALSE(etl::begin(sp) == etl::end(sp));

        auto counter = 0;
        etl::for_each(etl::begin(sp), etl::end(sp), [&counter](auto /*unused*/) { counter++; });
        CHECK(counter == 4);
    }

    {
        auto rng = [i = T{127}]() mutable { return T{i--}; };
        auto vec = etl::static_vector<T, 8>{};
        etl::generate_n(etl::back_inserter(vec), 4, rng);
        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};
        CHECK(sp[0] == T{127});
        CHECK(sp[1] == T{126});
        CHECK(sp[2] == T{125});
        CHECK(sp[3] == T{124});

        auto const csp = etl::span{sp};
        CHECK(csp[0] == T{127});
        CHECK(csp[1] == T{126});
        CHECK(csp[2] == T{125});
        CHECK(csp[3] == T{124});
    }

    {
        auto vec = etl::static_vector<T, 6>{};
        etl::generate_n(etl::back_inserter(vec), 4, []() { return T{42}; });
        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};

        CHECK(sp.size_bytes() == 4 * sizeof(T));
    }

    {
        auto data = etl::array{T(0), T(1), T(2), T(3), T(4), T(5), T(6)};
        auto sp   = etl::span<T>{data};

        auto one = sp.first(1);
        CHECK(one.size() == 1);
        CHECK(one[0] == T(0));

        auto two = sp.first(2);
        CHECK(two.size() == 2);
        CHECK(two[0] == T(0));
        CHECK(two[1] == T(1));

        auto onet = sp.template first<1>();
        CHECK(onet.size() == 1);
        CHECK(onet[0] == T(0));

        auto twot = sp.template first<2>();
        CHECK(twot.size() == 2);
        CHECK(twot[0] == T(0));
        CHECK(twot[1] == T(1));
    }

    {
        auto data = etl::array{T(0), T(1), T(2), T(3), T(4), T(5), T(6)};
        auto sp   = etl::span<T>{data};

        auto one = sp.last(1);
        CHECK(one.size() == 1);
        CHECK(one[0] == T(6));

        auto two = sp.last(2);
        CHECK(two.size() == 2);
        CHECK(two[0] == T(5));
        CHECK(two[1] == T(6));

        auto onet = sp.template last<1>();
        CHECK(onet.size() == 1);
        CHECK(onet[0] == T(6));

        auto twot = sp.template last<2>();
        CHECK(twot.size() == 2);
        CHECK(twot[0] == T(5));
        CHECK(twot[1] == T(6));
    }

    return true;
}

template <typename T>
static auto test_as_bytes() -> bool
{
    auto data = etl::array<T, 6>{};
    auto sp   = etl::span<T>{data};
    CHECK(etl::as_bytes(sp).size() == sizeof(T) * data.size());
    CHECK(etl::as_writable_bytes(sp).size() == sizeof(T) * data.size());
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());

    CHECK(test_as_bytes<etl::int8_t>());
    CHECK(test_as_bytes<etl::int16_t>());
    CHECK(test_as_bytes<etl::int32_t>());
    CHECK(test_as_bytes<etl::int64_t>());
    CHECK(test_as_bytes<etl::uint8_t>());
    CHECK(test_as_bytes<etl::uint16_t>());
    CHECK(test_as_bytes<etl::uint32_t>());
    CHECK(test_as_bytes<etl::uint64_t>());
    CHECK(test_as_bytes<float>());
    CHECK(test_as_bytes<double>());
    return 0;
}

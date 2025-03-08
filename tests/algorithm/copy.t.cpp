// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    using vector_t = etl::static_vector<T, 4>;

    // copy to c array
    {
        auto s = etl::array<T, 4>{T{1}, T{2}, T{3}, T{4}};
        T d[4] = {};
        etl::copy(begin(s), end(s), etl::begin(d));
        CHECK(d[0] == T{1});
        CHECK(d[1] == T{2});
        CHECK(d[2] == T{3});
        CHECK(d[3] == T{4});
    }

    // copy to vector
    {
        auto s = etl::array<T, 4>{T{1}, T{2}, T{3}, T{4}};
        auto d = vector_t{};
        CHECK(d.size() == 0);
        etl::copy(begin(s), end(s), etl::back_inserter(d));
        CHECK(d.size() == 4);
        CHECK(d[0] == T{1});
        CHECK(d[1] == T{2});
        CHECK(d[2] == T{3});
        CHECK(d[3] == T{4});
    }

    auto const s = etl::array{T(1), T(7), T(3), T(9)};

    auto p = [](auto val) { return static_cast<int>(val) >= 5; };

    // copy_if to c array
    {
        T d[4]    = {};
        auto* res = etl::copy_if(begin(s), end(s), etl::begin(d), p);
        CHECK(res == &d[2]);
        CHECK(d[0] == T{7});
        CHECK(d[1] == T{9});
        CHECK(d[2] == T{0});
        CHECK(d[3] == T{0});
    }

    // copy_if to vector
    {
        auto d = vector_t{};
        CHECK(d.size() == 0);
        etl::copy_if(begin(s), end(s), etl::back_inserter(d), p);
        CHECK(d.size() == 2);
        CHECK(d[0] == T{7});
        CHECK(d[1] == T{9});
    }

    // all elements
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        T dest[4]         = {};
        etl::copy_n(source.begin(), 4, etl::begin(dest));
        CHECK(dest[0] == T{1});
        CHECK(dest[1] == T{2});
        CHECK(dest[2] == T{3});
        CHECK(dest[3] == T{4});
    }

    // 2 elements
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        T dest[3]         = {};
        etl::copy_n(source.begin(), 2, etl::begin(dest));
        CHECK(dest[0] == T{1});
        CHECK(dest[1] == T{2});
        CHECK(dest[2] == T{0});
    }

    // copy_n to vector
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        auto dest         = vector_t{};
        CHECK(dest.size() == 0);
        etl::copy_n(source.begin(), source.size(), etl::back_inserter(dest));
        CHECK(dest.size() == 4);
        CHECK(dest[0] == T{1});
        CHECK(dest[1] == T{2});
        CHECK(dest[2] == T{3});
        CHECK(dest[3] == T{4});
    }

    // copy_backward to c array
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        T dest[4]         = {};
        etl::copy_backward(source.begin(), source.end(), etl::end(dest));
        CHECK(dest[0] == T{1});
        CHECK(dest[1] == T{2});
        CHECK(dest[2] == T{3});
        CHECK(dest[3] == T{4});
    }

    // input iterator
    {
        auto d = etl::static_vector<T, 4>{};
        etl::copy(InIter(begin(s)), InIter(end(s)), etl::back_inserter(d));
        CHECK(etl::equal(begin(s), end(s), begin(d), end(d)));
    }
    // forward iterator
    {
        auto d = etl::static_vector<T, 4>{};
        etl::copy(FwdIter(begin(s)), FwdIter(end(s)), etl::back_inserter(d));
        CHECK(etl::equal(begin(s), end(s), begin(d), end(d)));
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

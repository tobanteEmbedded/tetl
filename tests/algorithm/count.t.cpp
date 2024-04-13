// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto src = etl::array<T, 4>{};
    etl::iota(src.begin(), src.end(), T{0});

    CHECK(etl::count(src.begin(), src.end(), T{0}) == 1);
    CHECK(etl::count(src.begin(), src.end(), T{1}) == 1);
    CHECK(etl::count(src.begin(), src.end(), T{2}) == 1);
    CHECK(etl::count(src.begin(), src.end(), T{3}) == 1);
    CHECK(etl::count(src.begin(), src.end(), T{4}) == 0);

    // input iterator
    CHECK(etl::count(InIter(src.begin()), InIter(end(src)), T(0)) == 1);
    // forward iterator
    CHECK(etl::count(FwdIter(src.begin()), FwdIter(end(src)), T(0)) == 1);

    auto p1 = [](auto val) { return val < T{2}; };
    auto p2 = [](auto val) -> bool { return static_cast<int>(val) % 2; };

    CHECK(etl::count_if(src.begin(), src.end(), p1) == 2);
    CHECK(etl::count_if(src.begin(), src.end(), p2) == 2);

    // input iterator
    CHECK(etl::count_if(InIter(src.begin()), InIter(end(src)), p1) == 2);
    // forward iterator
    CHECK(etl::count_if(FwdIter(src.begin()), FwdIter(end(src)), p1) == 2);

    return true;
}

constexpr auto test_all() -> bool
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

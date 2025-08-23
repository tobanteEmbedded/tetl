// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/complex.hpp>
    #include <etl/tuple.hpp>
    #include <etl/utility.hpp>
#endif

namespace {

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::tuple_like<etl::array<T, 1>>);
    CHECK(etl::tuple_like<etl::array<T, 2>>);
    CHECK(etl::tuple_like<etl::array<T, 5>>);

    CHECK(etl::tuple_like<etl::complex<T>>);
    CHECK(etl::tuple_like<etl::pair<T, double>>);

    CHECK(etl::tuple_like<etl::tuple<T>>);
    CHECK(etl::tuple_like<etl::tuple<int, T>>);
    CHECK(etl::tuple_like<etl::tuple<int, T, char const*>>);

    CHECK(etl::pair_like<etl::complex<T>>);
    CHECK(etl::pair_like<etl::array<T, 2>>);
    CHECK(etl::pair_like<etl::pair<T, double>>);
    CHECK(etl::pair_like<etl::tuple<int, T>>);

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

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

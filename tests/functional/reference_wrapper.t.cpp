// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.algorithm;
import etl.array;
import etl.functional;
import etl.iterator;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/functional.hpp>
    #include <etl/iterator.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    auto original = etl::array<T, 4>{
        T(4),
        T(3),
        T(2),
        T(1),
    };

    auto sorted = etl::array<etl::reference_wrapper<T>, 4>{
        etl::ref(original[0]),
        etl::ref(original[1]),
        etl::ref(original[2]),
        etl::ref(original[3]),
    };
    etl::sort(begin(sorted), end(sorted));

    CHECK(original[0] == T(4));
    CHECK(original[1] == T(3));
    CHECK(original[2] == T(2));
    CHECK(original[3] == T(1));

    CHECK(sorted[0] == T(1));
    CHECK(sorted[1] == T(2));
    CHECK(sorted[2] == T(3));
    CHECK(sorted[3] == T(4));

    for (T& i : original) {
        i *= T(2);
    }
    CHECK(sorted[0] == T(2));
    CHECK(sorted[1] == T(4));
    CHECK(sorted[2] == T(6));
    CHECK(sorted[3] == T(8));

    auto lambda = [](T val) { return val; };
    CHECK(etl::ref(lambda)(T(0)) == T(0));
    CHECK(etl::cref(lambda)(T(42)) == T(42));
    CHECK(etl::ref(etl::ref(lambda))(T(42)) == T(42));
    CHECK(etl::cref(etl::cref(lambda))(T(42)) == T(42));

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

// SPDX-License-Identifier: BSL-1.0

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.algorithm;
import etl.array;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // cppreference.com example

    struct S {
        constexpr S(T n, char na)
            : number{n}
            , name{na}
        {
        }

        constexpr auto operator<(S const& s) const -> bool { return number < s.number; }

        T number;
        char name;
    };

    // note: not ordered, only partitioned w.r.t. S defined below
    auto vec = etl::array<S, 6>{
        S{T(1), 'A'},
        S{T(2), 'B'},
        S{T(2), 'C'},
        S{T(2), 'D'},
        S{T(4), 'G'},
        S{T(3), 'F'},
    };

    auto const value = S{T(2), '?'};
    auto const p     = etl::equal_range(vec.begin(), vec.end(), value);
    CHECK(p.first->name == 'B');

    CHECK(etl::equal_range(FwdIter(begin(vec)), FwdIter(end(vec)), value).first->name == 'B');

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

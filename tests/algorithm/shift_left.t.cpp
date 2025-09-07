// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    {
        auto data           = etl::array{T(1), T(2), T(3), T(4), T(5), T(6)};
        auto const original = data;

        etl::shift_left(data.begin(), data.end(), -1);
        CHECK(data == original);

        etl::shift_left(data.begin(), data.end(), 0);
        CHECK(data == original);

        etl::shift_left(data.begin(), data.end(), etl::ptrdiff_t(data.size() + 1));
        CHECK(data == original);

        CHECK(etl::shift_left(data.begin(), data.end(), etl::ptrdiff_t(data.size() + 1)) == data.begin());
        CHECK(data == original);

        etl::shift_left(data.begin(), data.end(), 2);
        CHECK(data[0] == T(3));
        CHECK(data[1] == T(4));
        CHECK(data[2] == T(5));
        CHECK(data[3] == T(6));
    }

    {
        auto data           = etl::array{T(1), T(2), T(3), T(4), T(5), T(6)};
        auto const original = data;

        etl::shift_left(FwdIter(data.begin()), FwdIter(data.end()), -1);
        CHECK(data == original);

        etl::shift_left(FwdIter(data.begin()), FwdIter(data.end()), 0);
        CHECK(data == original);

        etl::shift_left(FwdIter(data.begin()), FwdIter(data.end()), etl::ptrdiff_t(data.size() + 1));
        CHECK(data == original);

        CHECK(
            etl::shift_left(FwdIter(data.begin()), FwdIter(data.end()), etl::ptrdiff_t(data.size() + 1))
            == FwdIter(data.begin())
        );
        CHECK(data == original);

        etl::shift_left(FwdIter(data.begin()), FwdIter(data.end()), 2);
        CHECK(data[0] == T(3));
        CHECK(data[1] == T(4));
        CHECK(data[2] == T(5));
        CHECK(data[3] == T(6));
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

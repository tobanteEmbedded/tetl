// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/optional.hpp>
    #include <etl/ranges.hpp>
    #include <etl/type_traits.hpp>
#endif

namespace {

template <typename T>
constexpr auto test() -> bool
{
    using opt_t = etl::optional<T>;
    CHECK_SAME_TYPE(typename opt_t::value_type, T);
    CHECK_SAME_TYPE(typename opt_t::iterator, T*);
    CHECK_SAME_TYPE(typename opt_t::const_iterator, T const*);
    CHECK(etl::ranges::range<opt_t>);

    {
        auto hasValue = false;
        for (auto v : opt_t{}) {
            hasValue = v == T(42);
        }
        CHECK_FALSE(hasValue);
    }

    {
        auto hasValue = false;
        for (auto v : opt_t{T(42)}) {
            hasValue = v == T(42);
        }
        CHECK(hasValue);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

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

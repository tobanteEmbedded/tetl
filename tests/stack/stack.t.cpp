// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/stack.hpp>
    #include <etl/utility.hpp>
    #include <etl/vector.hpp>
#endif

template <typename T>
static auto test() -> bool
{
    using pair_type  = etl::pair<int, T>;
    using stack_type = etl::stack<pair_type, etl::static_vector<pair_type, 4>>;

    stack_type s{};
    CHECK(s.empty());

    s.push(etl::make_pair(1, T{2}));
    s.push(etl::make_pair(2, T{6}));
    s.push(etl::make_pair(3, T{51}));
    CHECK(s.size() == 3);
    CHECK(s.top().second == T{51});
    CHECK(s.size() == 3);

    s.pop();
    CHECK(etl::as_const(s).top().second == T{6});
    CHECK(s.size() == 2);

    s.emplace(42, T{1});
    CHECK(s.size() == 3);
    CHECK(s.top().first == 42);
    CHECK(s.top().second == T{1});

    auto sCopy = s;
    CHECK(sCopy == s);
    CHECK(s == sCopy);
    CHECK_FALSE(sCopy != s);
    CHECK_FALSE(s != sCopy);

    sCopy.pop();
    CHECK(sCopy != s);
    CHECK(s != sCopy);
    CHECK_FALSE(sCopy == s);
    CHECK_FALSE(s == sCopy);

    decltype(sCopy) sSwap{};
    sCopy.swap(sSwap);

    CHECK(sCopy.empty());
    CHECK(sSwap.size() == 2);
    return true;
}

static auto test_all() -> bool
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
    CHECK(test_all());

    // TODO: [tobi] Enable constexpr tests
    // static_assert(test_all());
    return 0;
}

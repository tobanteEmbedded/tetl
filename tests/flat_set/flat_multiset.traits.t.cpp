// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/flat_set.hpp>
    #include <etl/functional.hpp>
    #include <etl/inplace_vector.hpp>
    #include <etl/iterator.hpp>
    #include <etl/utility.hpp>
    #include <etl/vector.hpp>
#endif

namespace {

template <typename T, typename Container, typename Compare>
constexpr auto test() -> bool
{
    using set = etl::flat_multiset<T, Container, Compare>;

    CHECK_SAME_TYPE(typename set::key_type, T);
    CHECK_SAME_TYPE(typename set::key_compare, Compare);
    CHECK_SAME_TYPE(typename set::value_type, T);
    CHECK_SAME_TYPE(typename set::value_compare, Compare);
    CHECK_SAME_TYPE(typename set::reference, T&);
    CHECK_SAME_TYPE(typename set::const_reference, T const&);
    CHECK_SAME_TYPE(typename set::size_type, typename Container::size_type);
    CHECK_SAME_TYPE(typename set::difference_type, typename Container::difference_type);
    CHECK_SAME_TYPE(typename set::iterator, typename Container::iterator);
    CHECK_SAME_TYPE(typename set::const_iterator, typename Container::const_iterator);
    CHECK_SAME_TYPE(typename set::reverse_iterator, etl::reverse_iterator<typename Container::iterator>);
    CHECK_SAME_TYPE(typename set::const_reverse_iterator, etl::reverse_iterator<typename Container::const_iterator>);
    CHECK_SAME_TYPE(typename set::container_type, Container);

    if constexpr (etl::is_trivial_v<T>) {
        CHECK(set{}.max_size() == Container().max_size());
    }

    return true;
}

template <typename T>
constexpr auto test_type() -> bool
{
    CHECK(test<T, etl::static_vector<T, 4>, etl::less<>>());
    CHECK(test<T, etl::inplace_vector<T, 4>, etl::less<>>());

    CHECK(test<T, etl::static_vector<T, 8>, etl::less<T>>());
    CHECK(test<T, etl::inplace_vector<T, 8>, etl::less<T>>());

    CHECK(test<T, etl::static_vector<T, 4>, etl::greater<>>());
    CHECK(test<T, etl::inplace_vector<T, 4>, etl::greater<>>());

    CHECK(test<T, etl::static_vector<T, 8>, etl::greater<T>>());
    CHECK(test<T, etl::inplace_vector<T, 8>, etl::greater<T>>());
    return true;
}

constexpr auto test_all() -> bool
{
    struct Person {
        int age;
        int experience;
    };

    CHECK(test_type<signed char>());
    CHECK(test_type<signed short>());
    CHECK(test_type<signed int>());
    CHECK(test_type<signed long>());
    CHECK(test_type<signed long long>());

    CHECK(test_type<unsigned char>());
    CHECK(test_type<unsigned short>());
    CHECK(test_type<unsigned int>());
    CHECK(test_type<unsigned long>());
    CHECK(test_type<unsigned long long>());

    CHECK(test_type<char>());
    CHECK(test_type<char8_t>());
    CHECK(test_type<char16_t>());
    CHECK(test_type<char32_t>());
    CHECK(test_type<wchar_t>());

    CHECK(test_type<float>());
    CHECK(test_type<double>());
    CHECK(test_type<long double>());

    CHECK(test_type<Person>());
    CHECK(test_type<etl::pair<Person, Person>>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

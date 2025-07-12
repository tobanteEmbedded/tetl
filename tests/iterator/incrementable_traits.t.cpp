// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.concepts;
import etl.cstddef;
import etl.cstdint;
import etl.iterator;
import etl.type_traits;
#else
    #include <etl/concepts.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/iterator.hpp>
    #include <etl/type_traits.hpp>
#endif

namespace {

template <typename T>
struct value_wrapper {
    using value_type = T;
};

template <typename T>
struct iterator_wrapper {
    using value_type      = T;
    using difference_type = T;
};

template <typename T>
concept has_difference_type = requires { typename T::difference_type; };

template <typename T>
constexpr auto test() -> bool
{
    // builtin
    CHECK(etl::is_empty_v<etl::incrementable_traits<T>>);
    CHECK(has_difference_type<etl::incrementable_traits<T>> == etl::integral<T>);
    CHECK_FALSE(has_difference_type<etl::incrementable_traits<value_wrapper<T>>>);

    // builtin const
    CHECK(etl::is_empty_v<etl::incrementable_traits<T const>>);
    CHECK(has_difference_type<etl::incrementable_traits<T const>> == etl::integral<T const>);
    CHECK_FALSE(has_difference_type<etl::incrementable_traits<value_wrapper<T> const>>);

    // pointer
    CHECK(etl::is_empty_v<etl::incrementable_traits<T*>>);
    CHECK(has_difference_type<etl::incrementable_traits<T*>>);
    CHECK_FALSE(has_difference_type<etl::incrementable_traits<value_wrapper<T*>>>);
    CHECK_SAME_TYPE(typename etl::incrementable_traits<T*>::difference_type, etl::ptrdiff_t);

    // iterator
    CHECK(etl::is_empty_v<etl::incrementable_traits<iterator_wrapper<T>>>);
    CHECK(has_difference_type<etl::incrementable_traits<iterator_wrapper<T>>>);
    CHECK_SAME_TYPE(typename etl::incrementable_traits<iterator_wrapper<T>>::difference_type, T);

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

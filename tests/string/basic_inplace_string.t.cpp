// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
    #include <etl/string.hpp>
    #include <etl/string_view.hpp>
    #include <etl/utility.hpp>
#endif

namespace {

template <typename Char, typename String>
constexpr auto test() -> bool
{
    CHECK_SAME_TYPE(typename String::value_type, Char);
    CHECK_SAME_TYPE(typename String::size_type, etl::size_t);
    CHECK_SAME_TYPE(typename String::difference_type, etl::ptrdiff_t);
    CHECK_SAME_TYPE(typename String::traits_type, etl::char_traits<Char>);
    CHECK_SAME_TYPE(typename String::pointer, Char*);
    CHECK_SAME_TYPE(typename String::const_pointer, Char const*);
    CHECK_SAME_TYPE(typename String::reference, Char&);
    CHECK_SAME_TYPE(typename String::const_reference, Char const&);
    CHECK_SAME_TYPE(typename String::iterator, Char*);
    CHECK_SAME_TYPE(typename String::const_iterator, Char const*);
    CHECK_SAME_TYPE(typename String::reverse_iterator, etl::reverse_iterator<Char*>);
    CHECK_SAME_TYPE(typename String::const_reverse_iterator, etl::reverse_iterator<Char const*>);

    // construct(default)
    {
        auto const str = String();
        CHECK(str.empty());
        CHECK(str.size() == 0); // NOLINT
        CHECK(str.begin() == str.end());
        CHECK(str == str);
        CHECK_FALSE(str != str);
    }

    // construct(size, char)
    {
        auto const str = String(2, Char('A'));
        CHECK_FALSE(str.empty());
        CHECK(str.size() == 2);
        CHECK(str.begin() != str.end());

        CHECK_FALSE(str == String());
        CHECK_FALSE(String() == str);

        CHECK(str != String());
        CHECK(String() != str);

        CHECK_FALSE(str < String());
        CHECK(String() < str);

        CHECK_FALSE(str <= String());
        CHECK(String() <= str);

        CHECK(str > String());
        CHECK_FALSE(String() > str);

        CHECK(str >= String());
        CHECK_FALSE(String() >= str);
    }

    return true;
}

template <typename Char>
constexpr auto test_char_type() -> bool
{
    CHECK(test<Char, etl::basic_inplace_string<Char, 3>>());
    CHECK(test<Char, etl::basic_inplace_string<Char, 5>>());
    CHECK(test<Char, etl::basic_inplace_string<Char, 7>>());
    CHECK(test<Char, etl::basic_inplace_string<Char, 8>>());
    CHECK(test<Char, etl::basic_inplace_string<Char, 15>>());
    CHECK(test<Char, etl::basic_inplace_string<Char, 16>>());
    CHECK(test<Char, etl::basic_inplace_string<Char, 31>>());
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_char_type<char>());
    CHECK(test_char_type<wchar_t>());
    CHECK(test_char_type<char8_t>());
    CHECK(test_char_type<char16_t>());
    CHECK(test_char_type<char32_t>());
    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

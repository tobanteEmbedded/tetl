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

using namespace etl::string_view_literals;

template <typename String>
[[nodiscard]] static constexpr auto test() -> bool
{
    auto const empty  = String();
    auto const abcd   = String("abcd");
    auto const test   = String("test");
    auto const foo    = String("foo");
    auto const foobar = String("foobar");

    // contains
    CHECK(abcd.contains("ab"));
    CHECK(abcd.contains("ab"_sv));
    CHECK(abcd.contains('a'));
    CHECK_FALSE(abcd.contains("abf"_sv));
    CHECK_FALSE(abcd.contains('x'));

    // starts_with
    CHECK_FALSE(empty.starts_with("foo"_sv));
    CHECK_FALSE(empty.starts_with("foo"));
    CHECK_FALSE(empty.starts_with('f'));

    CHECK_FALSE(test.starts_with("foo"_sv));
    CHECK_FALSE(test.starts_with("foo"));
    CHECK_FALSE(test.starts_with('f'));

    CHECK(foo.starts_with("foo"_sv));
    CHECK(foo.starts_with("foo"));
    CHECK(foo.starts_with('f'));

    CHECK(foobar.starts_with("foo"_sv));
    CHECK(foobar.starts_with("foo"));
    CHECK(foobar.starts_with('f'));

    // ends_with
    CHECK_FALSE(empty.ends_with("foo"_sv));
    CHECK_FALSE(empty.ends_with("foo"));
    CHECK_FALSE(empty.ends_with('o'));

    CHECK_FALSE(test.ends_with("foo"_sv));
    CHECK_FALSE(test.ends_with("foo"));
    CHECK_FALSE(test.ends_with('o'));

    CHECK(foo.ends_with("foo"_sv));
    CHECK(foo.ends_with("foo"));
    CHECK(foo.ends_with('o'));

    CHECK(foobar.ends_with("bar"_sv));
    CHECK(foobar.ends_with("bar"));
    CHECK(foobar.ends_with('r'));

    // find
    {
        auto str = String();
        CHECK(str.find(String(), 0) == 0);
        CHECK(str.find(String(), 1) == String::npos);
        CHECK(str.find(String{""}) == 0);
    }

    {
        auto str = String{"def"};
        CHECK(str.find(String{"abc"}, 0) == String::npos);
        CHECK(str.find(String{"abc"}, 1) == String::npos);
        CHECK(str.find(String{"abc"}) == String::npos);
    }

    {
        auto str = String("abcd");
        CHECK(str.find(String{"abc"}, 0) == 0);
        CHECK(str.find(String{"bc"}, 1) == 1);
        CHECK(str.find(String{"cd"}) == 2);
    }

    {
        auto str = String();
        CHECK(str.find("") == 0);
        CHECK(str.find("", 0) == 0);
        CHECK(str.find("", 1) == String::npos);
    }

    {
        auto str = String{"def"};
        CHECK(str.find("abc", 0) == String::npos);
        CHECK(str.find("abc", 1) == String::npos);
        CHECK(str.find("abc") == String::npos);
    }

    {
        auto str = String("abcd");
        CHECK(str.find("abc", 0) == 0);
        CHECK(str.find("bc", 1) == 1);
        CHECK(str.find("cd") == 2);
    }

    {
        auto str = String();
        CHECK(str.find('a', 0) == String::npos);
        CHECK(str.find('a', 1) == String::npos);
        CHECK(str.find('a') == String::npos);
    }

    {
        auto str = String{"bcdef"};
        CHECK(str.find('a', 0) == String::npos);
        CHECK(str.find('a', 1) == String::npos);
        CHECK(str.find('a') == String::npos);
    }

    {
        auto str = String("abcd");
        CHECK(str.find('a', 0) == 0);
        CHECK(str.find('b', 1) == 1);
        CHECK(str.find('c') == 2);
    }

    // rfind
    {
        auto str = String("test");
        CHECK(str.rfind(String()) == 0);
        CHECK(str.rfind(String(), 0) == 0);
        CHECK(str.rfind(String(), String::npos) == str.size());
    }

    {
        auto str = String{"def"};
        CHECK(str.rfind(String{"abc"}, 0) == String::npos);
        CHECK(str.rfind(String{"abc"}, 1) == String::npos);
        CHECK(str.rfind(String{"abc"}) == String::npos);
    }

    {
        // auto const str = String ("test");
        // CHECK(str.rfind(String {"t"}) == 3);
        // CHECK(str.rfind(String {"est"}) == 1);

        // CHECK(str.rfind(String {"st"}, 12) == 2);
        // CHECK(str.rfind(String {"st"}, 12) == 2);
    }

    {
        auto str = String("test");
        CHECK(str.rfind("") == 0);
        CHECK(str.rfind("", 0) == 0);
        CHECK(str.rfind("", String::npos) == str.size());
    }

    {
        auto str = String{"def"};
        CHECK(str.rfind("abc", 0) == String::npos);
        CHECK(str.rfind("abc", 1) == String::npos);
        CHECK(str.rfind("abc") == String::npos);
    }

    {
        auto const str = String("test");
        CHECK(str.rfind("t") == 0);
        // CHECK(str.rfind("t", 1) == 3);
        // CHECK(str.rfind("est") == 1);

        // CHECK(str.rfind("st", 12) == 2);
        // CHECK(str.rfind("st", 12) == 2);
    }

    // find_first_of
    {
        auto str = String();
        CHECK(str.find_first_of(String(), 0) == String::npos);
        CHECK(str.find_first_of(String(), 1) == String::npos);
        CHECK(str.find_first_of(String{""}) == String::npos);
    }

    {
        auto str = String{"def"};
        CHECK(str.find_first_of(String{"abc"}, 0) == String::npos);
        CHECK(str.find_first_of(String{"abc"}, 1) == String::npos);
        CHECK(str.find_first_of(String{"abc"}) == String::npos);
    }

    {
        auto str = String("abcd");
        CHECK(str.find_first_of(String{"abc"}, 0) == 0);
        CHECK(str.find_first_of(String{"bc"}, 1) == 1);
        CHECK(str.find_first_of(String{"cd"}) == 2);
    }

    {
        auto str = String();
        CHECK(str.find_first_of("", 0) == String::npos);
        CHECK(str.find_first_of("", 1) == String::npos);
        CHECK(str.find_first_of("") == String::npos);
    }

    {
        CHECK(foo.find_first_of("abc", 0) == String::npos);
        CHECK(foo.find_first_of("abc", 1) == String::npos);
        CHECK(foo.find_first_of("abc") == String::npos);
    }

    {
        CHECK(abcd.find_first_of("abc", 0) == 0);
        CHECK(abcd.find_first_of("bc", 1) == 1);
        CHECK(abcd.find_first_of("cd") == 2);
    }

    {
        CHECK(empty.find_first_of(""_sv, 0) == String::npos);
        CHECK(empty.find_first_of(""_sv, 1) == String::npos);
        CHECK(empty.find_first_of(""_sv) == String::npos);
    }

    {
        CHECK(foo.find_first_of("abc"_sv, 0) == String::npos);
        CHECK(foo.find_first_of("abc"_sv, 1) == String::npos);
        CHECK(foo.find_first_of("abc"_sv) == String::npos);
    }

    {
        CHECK(abcd.find_first_of("abc"_sv, 0) == 0);
        CHECK(abcd.find_first_of("bc"_sv, 1) == 1);
        CHECK(abcd.find_first_of("cd"_sv) == 2);
    }

    {
        CHECK(empty.find_first_of('a', 0) == String::npos);
        CHECK(empty.find_first_of('a', 1) == String::npos);
        CHECK(empty.find_first_of('a') == String::npos);
    }

    {
        CHECK(foo.find_first_of('a', 0) == String::npos);
        CHECK(foo.find_first_of('a', 1) == String::npos);
        CHECK(foo.find_first_of('a') == String::npos);
    }

    {
        CHECK(abcd.find_first_of('a', 0) == 0);
        CHECK(abcd.find_first_of('b', 1) == 1);
        CHECK(abcd.find_first_of('c') == 2);
    }

    // find_last_of
    {
        CHECK(test.find_last_of("x") == test.npos);
        CHECK(test.find_last_of('x') == test.npos);
    }

    // find_last_not_of
    {
        CHECK(test.find_last_not_of(String("est")) == test.npos);
        CHECK(test.find_last_not_of("est") == test.npos);
        CHECK(test.find_last_not_of("s", 2) == 1);
        CHECK(test.find_last_not_of('s', 2) == 1);
    }

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_string<7>>());
    CHECK(test<etl::inplace_string<9>>());
    CHECK(test<etl::inplace_string<16>>());
    CHECK(test<etl::inplace_string<24>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

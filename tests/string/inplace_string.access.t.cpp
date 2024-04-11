// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/algorithm.hpp>
#include <etl/string_view.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename String>
[[nodiscard]] constexpr auto test() -> bool
{
    using string = String;

    {
        string str{"abc"};
        CHECK(str[0] == 'a');
        CHECK(str[1] == 'b');
        CHECK(str[2] == 'c');
    }

    {
        string const str{"abc"};
        CHECK(str[0] == 'a');
        CHECK(str[1] == 'b');
        CHECK(str[2] == 'c');
    }

    {
        string str{"aaa"};

        etl::for_each(str.begin(), str.end(), [](auto& c) { CHECK(c == char('a')); });
        for (auto const& c : str) {
            CHECK(c == char('a'));
        }
    }

    {
        string str{"aaa"};

        etl::for_each(str.cbegin(), str.cend(), [](auto const& c) { CHECK(c == char('a')); });
    }

    {
        string empty{};
        CHECK(empty.rbegin() == empty.rend());

        string str1{"test"};
        CHECK(str1.rbegin() != str1.rend());
        auto begin1 = str1.rbegin();
        CHECK(*begin1 == 't');
        begin1++;
        CHECK(*begin1 == 's');
        begin1++;
        CHECK(*begin1 == 'e');
        begin1++;
        CHECK(*begin1 == 't');
        begin1++;
        CHECK(begin1 == str1.rend());
    }

    {
        string empty{};
        CHECK(empty.crbegin() == empty.crend());

        string str1{"test"};
        CHECK(str1.crbegin() != str1.crend());
        auto begin1 = str1.crbegin();
        CHECK(*begin1 == 't');
        begin1++;
        CHECK(*begin1 == 's');
        begin1++;
        CHECK(*begin1 == 'e');
        begin1++;
        CHECK(*begin1 == 't');
        begin1++;
        CHECK(begin1 == str1.crend());
    }

    {
        auto str = string();
        str.append(4, 'a');

        CHECK(str.size() == etl::size_t(4));
        CHECK(str.length() == etl::size_t(4));
        CHECK(str[0] == 'a');
        CHECK(str[1] == 'a');
        CHECK(str[2] == 'a');
        CHECK(str[3] == 'a');
    }

    {
        string str{};

        // APPEND 4 CHARACTERS
        char const* cptr = "C-string";
        str.append(cptr, 4);

        CHECK(str.empty() == false);
        CHECK(str.capacity() == str.max_size());
        CHECK(str.size() == etl::size_t(4));
        CHECK(str.length() == etl::size_t(4));
        CHECK(str[0] == 'C');
        CHECK(str[1] == '-');
        CHECK(str[2] == 's');
        CHECK(str[3] == 't');
    }

    {
        string str{};
        char const* cptr = "C-string";
        str.append(cptr);

        CHECK(str[0] == 'C');
        CHECK(str[1] == '-');
        CHECK(str[2] == 's');
        CHECK(str[3] == 't');
    }

    {
        etl::string_view emptySrc{""};

        string empty{};
        empty.append(begin(emptySrc), end(emptySrc));
        CHECK(empty.empty());

        string str{"abc"};
        str.append(begin(emptySrc), end(emptySrc));
        CHECK(str == "abc"_sv);
    }

    {
        etl::string_view src{"_test"};

        string dest{"abc"};
        dest.append(src.begin(), src.end());
        CHECK(dest == "abc_test"_sv);
    }

    {
        string emptySrc{""};

        string empty{};
        empty.append(emptySrc);
        CHECK(empty.empty());

        string str{"abc"};
        str.append(emptySrc);
        CHECK(str == "abc"_sv);
    }

    {
        string src{"_test"};

        string dest{"abc"};
        dest.append(src);
        CHECK(dest == "abc_test"_sv);
    }

    {
        auto str = string{"BCDEF"};

        CHECK(str.find_first_not_of("ABC") == 2);
        CHECK(str.find_first_not_of("ABC", 4) == 4);
        CHECK(str.find_first_not_of('B') == 1);
        CHECK(str.find_first_not_of('D', 2) == 3);
    }

    {
        auto str = string();
        CHECK(str == "");

        str = str + "tes";
        CHECK(str == "tes");

        str = str + 't';
        CHECK(str == "test");

        str = str + string{"_foo"};
        CHECK(str == "test_foo");

        str = "__" + str;
        CHECK(str == "__test_foo");

        str = 'a' + str;
        CHECK(str == "a__test_foo");
    }

    {
        auto lhs = string();
        auto rhs = string();

        CHECK(lhs == "");
        CHECK(lhs == rhs);
        CHECK_FALSE(lhs != rhs);
        CHECK(rhs == lhs);
        CHECK_FALSE(rhs != lhs);
    }

    {
        auto lhs = string();
        auto rhs = etl::inplace_string<2>{};

        CHECK(lhs == "");
        CHECK(rhs == "");
        CHECK(lhs == rhs);
        CHECK_FALSE(lhs != rhs);
        CHECK_FALSE(lhs != "");
        CHECK(rhs == lhs);
        CHECK_FALSE(rhs != lhs);
    }

    {
        CHECK_FALSE(string{} < "");
        CHECK_FALSE(string{} < string{});
        CHECK_FALSE(string{} < etl::inplace_string<2>{});
        CHECK_FALSE(etl::inplace_string<4>{} < string{});
    }

    {
        CHECK(string{"abc"} < "def");
        CHECK(string{"abc"} < string{"def"});
        CHECK(string{"abc"} < string{"defg"});
    }

    {
        CHECK_FALSE(string{"def"} < "a");
        CHECK_FALSE(string{"def"} < etl::inplace_string<2>{"a"});
        CHECK(etl::inplace_string<2>{"a"} < string("test"));
    }

    {
        CHECK(string{} <= "");
        CHECK(string{} <= string{});
        CHECK(string{} <= etl::inplace_string<2>{});
        CHECK(etl::inplace_string<4>{} <= string{});
    }

    {
        CHECK(string{"abc"} <= "def");
        CHECK(string{"abc"} <= string{"def"});
        CHECK(string{"abc"} <= string{"defg"});
        CHECK(string{"abc"} <= string{"abc"});
    }

    {
        CHECK_FALSE(string{"def"} <= "a");
        CHECK_FALSE(string{"def"} <= etl::inplace_string<2>{"a"});
        CHECK(etl::inplace_string<2>{"a"} <= string("test"));
    }

    {
        CHECK_FALSE(string{} > "");
        CHECK_FALSE(string{} > string{});
        CHECK_FALSE(string{} > etl::inplace_string<2>{});
        CHECK_FALSE(etl::inplace_string<4>{} > string{});
    }

    {
        CHECK_FALSE(string{"abc"} > "def");
        CHECK_FALSE(string{"abc"} > string{"def"});
        CHECK_FALSE(string{"abc"} > string{"defg"});
        CHECK_FALSE(string{"abc"} > string{"abc"});
    }

    {
        CHECK(string{"def"} > etl::inplace_string<2>{"a"});
        CHECK_FALSE(etl::inplace_string<2>{"a"} > string("test"));
    }

    {
        CHECK(string{} >= "");
        CHECK(string{} >= string{});
        CHECK(string{} >= etl::inplace_string<2>{});
        CHECK(etl::inplace_string<4>{} >= string{});
    }

    {
        CHECK(string{"abc"} >= "abc");
        CHECK(string{"abc"} >= string{"abc"});
        CHECK_FALSE(string{"abc"} >= string{"def"});
        CHECK_FALSE(string{"abc"} >= string{"defg"});
    }

    {
        CHECK(string{"def"} >= etl::inplace_string<2>{"a"});
        CHECK_FALSE(etl::inplace_string<2>{"a"} >= string("test"));
    }

    {
        auto str = string();
        CHECK(str.substr().size() == 0);
        CHECK(str.substr(1).size() == 0);
        CHECK(str.substr(10).size() == 0);
    }

    {
        auto str = string("abcd");
        CHECK(str.size() == 4);
        CHECK(str.substr(0, 1).size() == 1);
        CHECK(str.substr(1).size() == 3);
        CHECK(str.substr(10).size() == 0);
    }

    {
        char destination[32] = {};
        auto str             = string();
        CHECK(str.empty());
        CHECK(str.copy(destination, 0, 0) == 0);
        CHECK(str.copy(destination, 1, 0) == 0);
        CHECK(str.copy(destination, 10, 1) == 0);
    }

    {
        char destination[32] = {};
        auto const* src      = "abcd";
        auto str             = string{src};
        CHECK(str.size() == 4);

        CHECK(str.copy(destination, 1, 0) == 1);
        CHECK(destination[0] == 'a');
        CHECK(destination[1] == '\0');

        CHECK(str.copy(destination, 2, 2) == 2);
        CHECK(destination[0] == 'c');
        CHECK(destination[1] == 'd');
        CHECK(destination[2] == '\0');

        CHECK(str.copy(destination, str.size()) == 4);
        CHECK(destination[0] == 'a');
        CHECK(destination[1] == 'b');
        CHECK(destination[2] == 'c');
        CHECK(destination[3] == 'd');
        CHECK(destination[4] == '\0');
    }

    {
        auto lhs = string();
        auto rhs = string();
        CHECK(lhs.empty());
        CHECK(rhs.empty());

        lhs.swap(rhs);
        CHECK(lhs.empty());
        CHECK(rhs.empty());
    }

    {
        auto lhs = string{"abc"};
        auto rhs = string{"def"};
        CHECK(lhs.size() == rhs.size());

        etl::swap(lhs, rhs);
        CHECK(lhs.size() == rhs.size());

        CHECK(lhs == "def");
        CHECK(rhs == "abc");
    }

    {
        auto lhs = string("foo");
        auto rhs = string{"barbaz"};
        CHECK(lhs.size() != rhs.size());

        lhs.swap(rhs);
        CHECK(lhs.size() != rhs.size());

        CHECK(lhs == "barbaz");
        CHECK(rhs == "foo");
    }

    {
        auto lhs = string();
        auto rhs = string();

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    {
        auto lhs = string();
        auto rhs = etl::inplace_string<2>{};

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    {
        auto const lhs = string("test");
        auto const rhs = string("test");

        CHECK(lhs.compare("test") == 0);
        CHECK(lhs.compare("test"_sv) == 0);
        CHECK(lhs.compare("test1"_sv) == -1);
        CHECK(lhs.compare("tes"_sv) == +1);
        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);

        CHECK(lhs.compare(1, 1, "test") < 0);
        CHECK(lhs.compare(1, 1, "test"_sv) < 0);
        CHECK(lhs.compare(1, 1, rhs) < 0);
        CHECK(rhs.compare(1, 1, lhs) < 0);

        CHECK(lhs.compare(1, 1, rhs, 1, 1) == 0);
        CHECK(rhs.compare(1, 1, lhs, 1, 1) == 0);

        CHECK(string("te").compare(0, 2, "test"_sv, 0, 2) == 0);
        CHECK(string("abcabc").compare(3, 3, "abc"_sv, 0, 3) == 0);
        CHECK(string("abcabc").compare(3, 1, "abc"_sv, 0, 3) < 0);
        CHECK(string("abcabc").compare(3, 3, "abc"_sv, 0, 1) > 0);

        CHECK(string("abcabc").compare(3, 3, "abc", 3) == 0);
        CHECK(string("abcabc").compare(3, 1, "abc", 0, 3) < 0);
        CHECK(string("abcabc").compare(3, 3, "abc", 0, 1) > 0);
    }

    {
        string emptySrc{""};

        string empty{};
        empty.append(emptySrc, 0);
        CHECK(empty.empty());

        string str{"abc"};
        str.append(emptySrc, 1);
        CHECK(str == "abc"_sv);
    }

    {
        string src{"_test"};

        string dest{"abc"};
        dest.append(src, 2, 2);
        CHECK(dest == "abces"_sv);
    }

    {
        etl::string_view emptySrc{""};

        string empty{};
        empty.append(emptySrc);
        CHECK(empty.empty());

        string str{"abc"};
        str.append(emptySrc);
        CHECK(str == "abc"_sv);
    }

    {
        etl::string_view src{"_test"};

        string dest{"abc"};
        dest.append(src);
        CHECK(dest == "abc_test"_sv);
    }

    {
        etl::string_view emptySrc{};

        string empty{};
        empty.append(emptySrc, 0);
        CHECK(empty.empty());
    }

    {
        etl::string_view src{"_test"};

        string dest{"abc"};
        dest.append(src, 2, 1);
        CHECK(dest == "abce"_sv);
    }

    {
        string src{"_test"};
        string dest{"abc"};
        dest += src;
        CHECK(dest == "abc_test"_sv);
    }

    {
        auto src = 'a';
        string dest{"abc"};
        dest += src;
        CHECK(dest == "abca"_sv);
    }

    {
        auto const* src = "_test";
        string dest{"abc"};
        dest += src;
        CHECK(dest == "abc_test"_sv);
    }

    {
        etl::string_view src{"_test"};
        string dest{"abc"};
        dest += src;
        CHECK(dest == "abc_test"_sv);
    }

    {
        // setup
        string str{"aaaaaa"};
        etl::for_each(str.begin(), str.end(), [](auto& c) { c++; });

        // test
        etl::for_each(str.cbegin(), str.cend(), [](auto const& c) { CHECK(c == 'b'); });

        CHECK(str.front() == 'b');
        CHECK(str.back() == 'b');
    }

    {
        string str{"junk"};
        CHECK(str.front() == 'j');
        CHECK(etl::as_const(str).front() == 'j');

        CHECK(str.back() == 'k');
        CHECK(etl::as_const(str).back() == 'k');
    }

    {
        string str{"junk"};
        CHECK(str.data() == str.c_str());
        CHECK(str.c_str() != nullptr);
        CHECK(str.c_str()[0] == 'j');
    }

    {
        string str{"junk"};
        auto sv = etl::string_view{str};
        CHECK(sv.data()[0] == 'j');
    }

    {
        // setup
        string str{"junk"};
        CHECK(str.empty() == false);

        // test
        str.clear();
        CHECK(str.capacity() == str.max_size());
        CHECK(str.empty() == true);
        CHECK(str.size() == etl::size_t(0));
    }

    {
        auto str = string();
        CHECK(str.empty() == true);

        // grow
        str.resize(2);
        CHECK(str.empty() == false);
        CHECK(str.size() == 2);
        CHECK(str[0] == '\0');
        CHECK(str[1] == '\0');

        // shrink
        str.resize(1);
        CHECK(str.empty() == false);
        CHECK(str.size() == 1);
        CHECK(str[0] == '\0');
    }

    {
        auto str = string();
        CHECK(str.empty() == true);

        // grow
        str.resize(2, 'a');
        CHECK(str.empty() == false);
        CHECK(str.size() == 2);
        CHECK(str[0] == 'a');
        CHECK(str[1] == 'a');

        // shrink
        str.resize(1, 'a');
        CHECK(str.empty() == false);
        CHECK(str.size() == 1);
        CHECK(str[0] == 'a');
    }

    {
        auto const lhs = string("test");
        auto const rhs = string("te");

        CHECK(lhs.compare(rhs) > 0);
        CHECK(rhs.compare("test"_sv) < 0);

        auto other = etl::inplace_string<9>{"te"};
        CHECK(lhs.compare(other) > 0);
        CHECK(other.compare(etl::string_view("te")) == 0);
    }

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_string<18>>());
    CHECK(test<etl::inplace_string<22>>());
    CHECK(test<etl::inplace_string<31>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

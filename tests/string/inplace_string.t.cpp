// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/algorithm.hpp>
#include <etl/string_view.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
[[nodiscard]] constexpr auto test_1() -> bool
{
    using string = T;

    {
        string str{};

        CHECK_FALSE(str.full());
        CHECK(str.empty());
        CHECK(str.capacity() == str.max_size());
        CHECK(str.size() == etl::size_t(0));
        CHECK(str.length() == etl::size_t(0));
    }

    {
        auto testCtorChar = [](etl::size_t size, char ch) {
            using string_t = T;
            auto str       = string_t{size, ch};
            CHECK_FALSE(str.empty());
            CHECK_FALSE(str.full());
            CHECK(str.size() == size);

            auto equal = [ch](auto c) { return c == ch; };
            CHECK(etl::all_of(begin(str), end(str), equal));
            return true;
        };

        CHECK(testCtorChar(1, 'x'));
        CHECK(testCtorChar(2, 'x'));
        CHECK(testCtorChar(2, 'x'));
        CHECK(testCtorChar(3, 'x'));
        CHECK(testCtorChar(10, 'x'));
        CHECK(testCtorChar(20, 'x'));
    }

    {
        auto testCtorCharPointerSize = [](char const* s, etl::size_t size) {
            using string_t = T;
            string_t str{s, size};
            CHECK_FALSE(str.full());
            CHECK(str.capacity() == str.max_size());
            CHECK(str.size() == size);
            CHECK(str.length() == size);
            CHECK(str == etl::string_view{s});
            return true;
        };

        CHECK(testCtorCharPointerSize("", 0));
        CHECK(testCtorCharPointerSize("a", 1));
        CHECK(testCtorCharPointerSize("ab", 2));
        CHECK(testCtorCharPointerSize("to", 2));
        CHECK(testCtorCharPointerSize("abc", 3));
        CHECK(testCtorCharPointerSize("foo_bar", 7));
        CHECK(testCtorCharPointerSize("foo bar", 7));
        CHECK(testCtorCharPointerSize("foo?bar", 7));
        CHECK(testCtorCharPointerSize("foo\nbar", 7));
        CHECK(testCtorCharPointerSize("xxxxxxxxxx", 10));
    }

    {
        auto testCtorCharPointers = [](char const* s, etl::size_t size) {
            using string_t = T;
            string_t str{s, etl::next(s, static_cast<etl::ptrdiff_t>(size))};
            CHECK_FALSE(str.full());
            CHECK(str.capacity() == str.max_size());
            CHECK(str.size() == size);
            CHECK(str.length() == size);
            CHECK(str == etl::string_view{s});
            return true;
        };

        CHECK(testCtorCharPointers("a", 1));
        CHECK(testCtorCharPointers("ab", 2));
        CHECK(testCtorCharPointers("to", 2));
        CHECK(testCtorCharPointers("abc", 3));
        CHECK(testCtorCharPointers("foo_bar", 7));
        CHECK(testCtorCharPointers("foo bar", 7));
        CHECK(testCtorCharPointers("foo?bar", 7));
        CHECK(testCtorCharPointers("foo\nbar", 7));
        CHECK(testCtorCharPointers("xxxxxxxxxx", 10));
    }

    {
        string src{"testabc"};

        string dest1(src, 0, 2);
        CHECK(dest1 == "te"_sv);

        string dest2(src, 4, 2);
        CHECK(dest2 == "ab"_sv);

        auto dest3 = string(src, 9, 2);
        CHECK(dest3 == ""_sv);
    }

    {
        etl::string_view sv{"test"};
        string dest{sv};

        CHECK_FALSE(dest.full());
        CHECK(dest.size() == etl::size_t(4));
        CHECK(dest.length() == etl::size_t(4));
        CHECK(dest[0] == 't');
        CHECK(dest[1] == 'e');
        CHECK(dest[2] == 's');
        CHECK(dest[3] == 't');
    }

    {
        etl::string_view sv{"test"};
        string dest{sv, 2, 2};

        CHECK_FALSE(dest.full());
        CHECK(dest.size() == etl::size_t(2));
        CHECK(dest.length() == etl::size_t(2));
        CHECK(dest[0] == 's');
        CHECK(dest[1] == 't');
    }

    {
        string src1{};
        string str1{};
        str1 = src1;
        CHECK(str1.size() == 0);
        CHECK(str1.empty());

        string src2{"test"};
        string str2{};
        str2 = src2;
        CHECK(str2.size() == 4);
        CHECK(str2 == "test"_sv);

        auto src3 = string{"abc"};
        string str3;
        str3 = src3;
        CHECK(str3.size() == 3);
        CHECK(str3 == "abc"_sv);
    }

    {
        auto const* src2 = "test";
        string str2{};
        str2 = src2;
        CHECK(str2.size() == 4);
        CHECK(str2 == "test"_sv);

        auto const* src3 = "abc";
        string str3;
        str3 = src3;
        CHECK(str3.size() == 3);
        CHECK(str3 == "abc"_sv);
    }

    {
        auto const src2 = 'a';
        string str2{};
        str2 = src2;
        CHECK(str2.size() == 1);
        CHECK(str2 == "a"_sv);

        auto const src3 = 'b';
        string str3;
        str3 = src3;
        CHECK(str3.size() == 1);
        CHECK(str3 == "b"_sv);
    }

    {
        etl::string_view src1{};
        string str1{};
        str1 = src1;
        CHECK(str1.size() == 0);

        etl::string_view src2{"test"};
        string str2{};
        str2 = src2;
        CHECK(str2.size() == 4);
        CHECK(str2 == "test"_sv);

        auto src3 = "abc"_sv;
        string str3;
        str3 = src3;
        CHECK(str3.size() == 3);
        CHECK(str3 == "abc"_sv);
    }

    return true;
}

template <typename T>
[[nodiscard]] constexpr auto test_2() -> bool
{
    using string = T;

    {
        string dest{};

        auto const src1 = string{};
        dest.assign(src1);
        CHECK(dest.size() == 0);
        CHECK(dest.empty());

        auto const src2 = string{"test"};
        dest.assign(src2);
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        auto src3 = string{"abc"};
        dest.assign(etl::move(src3));
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        auto const src4 = string{"abc"};
        dest.assign(src4, 1, 1);
        CHECK(dest.size() == 1);
        CHECK(dest == "b"_sv);
    }

    {
        string dest{};

        dest.assign(""_sv);
        CHECK(dest.size() == 0);
        CHECK(dest.empty());

        dest.assign("test"_sv);
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        dest.assign("abc"_sv);
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        dest.assign("abc"_sv, 0);
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        dest.assign("abc"_sv, 1);
        CHECK(dest.size() == 2);
        CHECK(dest == "bc"_sv);

        dest.assign("abc"_sv, 1, 1);
        CHECK(dest.size() == 1);
        CHECK(dest == "b"_sv);

        auto const src = etl::inplace_string<8>{"abc"};
        dest.assign(src);
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        dest.assign(src, 1, 1);
        CHECK(dest.size() == 1);
        CHECK(dest == "b"_sv);
    }

    {
        string dest{};

        auto src1 = "test"_sv;
        dest.assign(begin(src1), end(src1));
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        auto src2 = "abc"_sv;
        dest.assign(begin(src2), end(src2) - 1);
        CHECK(dest.size() == 2);
        CHECK(dest == "ab"_sv);
    }

    {
        string dest{};

        dest.assign("test");
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        dest.assign("abc");
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);
    }

    {
        string dest{};

        dest.assign(1, 'a');
        CHECK(dest.size() == 1);
        CHECK(dest == "a"_sv);

        dest.assign(4, 'z');
        CHECK(dest.size() == 4);
        CHECK(dest == "zzzz"_sv);
    }

    {
        string str{"abc"};
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
        string str{""};
        str.push_back('a');
        str.push_back('b');
        CHECK(str == string("ab"));
        CHECK(str.size() == 2);
    }

    {
        string str{"abc"};
        str.pop_back();
        str.pop_back();
        CHECK(str == string("a"));
        CHECK(str == "a");
        CHECK(str.size() == 1);
    }

    {
        auto str = string();
        str.insert(0, 4, 'a');
        CHECK(str.size() == 4);
        CHECK(str == "aaaa"_sv);
    }

    {
        auto str = string("test");
        str.insert(0, 4, 'a');
        CHECK(str.size() == 8);
        CHECK(str == "aaaatest"_sv);

        str = string("test");
        str.insert(1, 2, 'a');
        str.insert(0, 1, 'b');
        CHECK(str.size() == 7);
        CHECK(str == "btaaest"_sv);

        str = string("test");
        str.insert(str.size(), 2, 'a');
        CHECK(str.size() == 6);
        CHECK(str == "testaa"_sv);
    }

    {
        auto str = string("");
        str.insert(0, str.capacity(), 'a');
        CHECK(str.full());
        CHECK(str.size() == str.capacity());
        CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }

    {
        auto str = string();
        str.insert(0, "aaaa");
        CHECK(str.size() == 4);
        CHECK(str == "aaaa"_sv);
    }

    {
        auto str = string("test");
        str.insert(0, "abcd");
        CHECK(str.size() == 8);
        CHECK(str == "abcdtest"_sv);

        str = string("test");
        str.insert(1, "aa");
        str.insert(0, "b");
        CHECK(str.size() == 7);
        CHECK(str == "btaaest"_sv);

        str = string("test");
        str.insert(str.size(), "aa");
        CHECK(str.size() == 6);
        CHECK(str == "testaa"_sv);
    }

    {
        auto str = string("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) {
            str.insert(0, "a");
        }

        CHECK(str.full());
        CHECK(str.size() == str.capacity());
        CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }

    {
        auto str = string();
        str.insert(0, "aaaa", 4);
        CHECK(str.size() == 4);
        CHECK(str == "aaaa"_sv);
    }

    {
        auto str = string("test");
        str.insert(0, "abcd", 3);
        CHECK(str.size() == 7);
        CHECK(str == "abctest"_sv);

        str = string("test");
        str.insert(1, "aa", 2);
        str.insert(0, "b", 1);
        CHECK(str.size() == 7);
        CHECK(str == "btaaest"_sv);

        str = string("test");
        str.insert(str.size(), "aa", 1);
        CHECK(str.size() == 5);
        CHECK(str == "testa"_sv);
    }

    {
        auto str = string("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) {
            str.insert(0, "ab", 1);
        }

        CHECK(str.full());
        CHECK(str.size() == str.capacity());
        CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }

    {
        string str = "This is an example";

        // Erase "This "
        str.erase(0, 5);
        CHECK(str == "is an example"_sv);

        // Erase ' '
        CHECK(*str.erase(etl::find(begin(str), end(str), ' ')) == 'a');
        CHECK(str == "isan example"_sv);

        // Trim from ' ' to the end of the string
        str.erase(str.find(' '));
        CHECK(str == "isan"_sv);
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
        auto str = string();
        CHECK_FALSE(str.starts_with("foo"_sv));
        CHECK_FALSE(str.starts_with("foo"));
        CHECK_FALSE(str.starts_with('f'));
    }

    {
        auto str = string("test");
        CHECK_FALSE(str.starts_with("foo"_sv));
        CHECK_FALSE(str.starts_with("foo"));
        CHECK_FALSE(str.starts_with('f'));
    }

    {
        auto str1 = string("foo");
        CHECK(str1.starts_with("foo"_sv));
        CHECK(str1.starts_with("foo"));
        CHECK(str1.starts_with('f'));

        auto str2 = string{"foobar"};
        CHECK(str2.starts_with("foo"_sv));
        CHECK(str2.starts_with("foo"));
        CHECK(str2.starts_with('f'));
    }

    {
        auto str = string();
        CHECK_FALSE(str.ends_with("foo"_sv));
        CHECK_FALSE(str.ends_with("foo"));
        CHECK_FALSE(str.ends_with('o'));
    }

    {
        auto str = string("test");
        CHECK_FALSE(str.ends_with("foo"_sv));
        CHECK_FALSE(str.ends_with("foo"));
        CHECK_FALSE(str.ends_with('o'));
    }

    {
        auto str = string("foo");
        CHECK(str.ends_with("foo"_sv));
        CHECK(str.ends_with("foo"));
        CHECK(str.ends_with('o'));

        auto str2 = string("barfoo");
        CHECK(str2.ends_with("foo"_sv));
        CHECK(str2.ends_with("foo"));
        CHECK(str2.ends_with('o'));
    }

    {
        using string_t = string;

        auto s = string_t("0123456");
        CHECK(s.replace(0, 2, string_t("xx")) == "xx23456"_sv);
        CHECK(s.replace(2, 1, string_t("xx")) == "xxx3456"_sv);
        CHECK(s.replace(begin(s) + 3, begin(s) + 4, string_t("x")) == "xxxx456"_sv);
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

    {
        auto str = string();
        CHECK(str.find(string(), 0) == 0);
        CHECK(str.find(string(), 1) == string::npos);
        CHECK(str.find(string{""}) == 0);
    }

    {
        auto str = string{"def"};
        CHECK(str.find(string{"abc"}, 0) == string::npos);
        CHECK(str.find(string{"abc"}, 1) == string::npos);
        CHECK(str.find(string{"abc"}) == string::npos);
    }

    {
        auto str = string("abcd");
        CHECK(str.find(string{"abc"}, 0) == 0);
        CHECK(str.find(string{"bc"}, 1) == 1);
        CHECK(str.find(string{"cd"}) == 2);
    }

    {
        auto str = string();
        CHECK(str.find("") == 0);
        CHECK(str.find("", 0) == 0);
        CHECK(str.find("", 1) == string::npos);
    }

    {
        auto str = string{"def"};
        CHECK(str.find("abc", 0) == string::npos);
        CHECK(str.find("abc", 1) == string::npos);
        CHECK(str.find("abc") == string::npos);
    }

    {
        auto str = string("abcd");
        CHECK(str.find("abc", 0) == 0);
        CHECK(str.find("bc", 1) == 1);
        CHECK(str.find("cd") == 2);
    }

    {
        auto str = string();
        CHECK(str.find('a', 0) == string::npos);
        CHECK(str.find('a', 1) == string::npos);
        CHECK(str.find('a') == string::npos);
    }

    {
        auto str = string{"bcdef"};
        CHECK(str.find('a', 0) == string::npos);
        CHECK(str.find('a', 1) == string::npos);
        CHECK(str.find('a') == string::npos);
    }

    {
        auto str = string("abcd");
        CHECK(str.find('a', 0) == 0);
        CHECK(str.find('b', 1) == 1);
        CHECK(str.find('c') == 2);
    }

    {
        auto str = string("test");
        CHECK(str.rfind(string()) == 0);
        CHECK(str.rfind(string(), 0) == 0);
        CHECK(str.rfind(string(), string::npos) == str.size());
    }

    {
        auto str = string{"def"};
        CHECK(str.rfind(string{"abc"}, 0) == string::npos);
        CHECK(str.rfind(string{"abc"}, 1) == string::npos);
        CHECK(str.rfind(string{"abc"}) == string::npos);
    }

    {
        // auto const str = string ("test");
        // CHECK(str.rfind(string {"t"}) == 3);
        // CHECK(str.rfind(string {"est"}) == 1);

        // CHECK(str.rfind(string {"st"}, 12) == 2);
        // CHECK(str.rfind(string {"st"}, 12) == 2);
    }

    {
        auto str = string("test");
        CHECK(str.rfind("") == 0);
        CHECK(str.rfind("", 0) == 0);
        CHECK(str.rfind("", string::npos) == str.size());
    }

    {
        auto str = string{"def"};
        CHECK(str.rfind("abc", 0) == string::npos);
        CHECK(str.rfind("abc", 1) == string::npos);
        CHECK(str.rfind("abc") == string::npos);
    }

    {
        auto const str = string("test");
        CHECK(str.rfind("t") == 0);
        // CHECK(str.rfind("t", 1) == 3);
        // CHECK(str.rfind("est") == 1);

        // CHECK(str.rfind("st", 12) == 2);
        // CHECK(str.rfind("st", 12) == 2);
    }

    {
        auto str = string();
        CHECK(str.find_first_of(string(), 0) == string::npos);
        CHECK(str.find_first_of(string(), 1) == string::npos);
        CHECK(str.find_first_of(string{""}) == string::npos);
    }

    {
        auto str = string{"def"};
        CHECK(str.find_first_of(string{"abc"}, 0) == string::npos);
        CHECK(str.find_first_of(string{"abc"}, 1) == string::npos);
        CHECK(str.find_first_of(string{"abc"}) == string::npos);
    }

    {
        auto str = string("abcd");
        CHECK(str.find_first_of(string{"abc"}, 0) == 0);
        CHECK(str.find_first_of(string{"bc"}, 1) == 1);
        CHECK(str.find_first_of(string{"cd"}) == 2);
    }

    {
        auto str = string();
        CHECK(str.find_first_of("", 0) == string::npos);
        CHECK(str.find_first_of("", 1) == string::npos);
        CHECK(str.find_first_of("") == string::npos);
    }

    {
        auto str = string{"def"};
        CHECK(str.find_first_of("abc", 0) == string::npos);
        CHECK(str.find_first_of("abc", 1) == string::npos);
        CHECK(str.find_first_of("abc") == string::npos);
    }

    {
        auto str = string("abcd");
        CHECK(str.find_first_of("abc", 0) == 0);
        CHECK(str.find_first_of("bc", 1) == 1);
        CHECK(str.find_first_of("cd") == 2);
    }

    {
        auto str = string();
        CHECK(str.find_first_of(""_sv, 0) == string::npos);
        CHECK(str.find_first_of(""_sv, 1) == string::npos);
        CHECK(str.find_first_of(""_sv) == string::npos);
    }

    {
        auto str = string{"def"};
        CHECK(str.find_first_of("abc"_sv, 0) == string::npos);
        CHECK(str.find_first_of("abc"_sv, 1) == string::npos);
        CHECK(str.find_first_of("abc"_sv) == string::npos);
    }

    {
        auto str = string("abcd");
        CHECK(str.find_first_of("abc"_sv, 0) == 0);
        CHECK(str.find_first_of("bc"_sv, 1) == 1);
        CHECK(str.find_first_of("cd"_sv) == 2);
    }

    {
        auto str = string();
        CHECK(str.find_first_of('a', 0) == string::npos);
        CHECK(str.find_first_of('a', 1) == string::npos);
        CHECK(str.find_first_of('a') == string::npos);
    }

    {
        auto str = string{"def"};
        CHECK(str.find_first_of('a', 0) == string::npos);
        CHECK(str.find_first_of('a', 1) == string::npos);
        CHECK(str.find_first_of('a') == string::npos);
    }

    {
        auto str = string("abcd");
        CHECK(str.find_first_of('a', 0) == 0);
        CHECK(str.find_first_of('b', 1) == 1);
        CHECK(str.find_first_of('c') == 2);
    }

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(sizeof(etl::inplace_string<6>) == 7);   // tiny storage, size_type = uint8
    CHECK(sizeof(etl::inplace_string<7>) == 8);   // tiny storage, size_type = uint8
    CHECK(sizeof(etl::inplace_string<16>) == 18); // normal storage, size_type = uint8

    CHECK(test_1<etl::inplace_string<24>>());
    CHECK(test_1<etl::inplace_string<55>>());

    CHECK(test_2<etl::inplace_string<24>>());
    CHECK(test_2<etl::inplace_string<55>>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

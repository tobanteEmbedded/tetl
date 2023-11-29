// SPDX-License-Identifier: BSL-1.0

#include "etl/string.hpp"

#include "etl/algorithm.hpp"
#include "etl/string_view.hpp"
#include "etl/utility.hpp"

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
[[nodiscard]] constexpr auto test_1() -> bool
{
    using string = T;

    {
        string str {};

        assert(!str.full());
        assert(str.empty());
        assert(str.capacity() == str.max_size());
        assert(str.size() == etl::size_t(0));
        assert(str.length() == etl::size_t(0));
    }

    {
        auto testCtorChar = [](etl::size_t size, char ch) {
            using string_t = T;
            auto str       = string_t { size, ch };
            assert(!str.empty());
            assert(!str.full());
            assert(str.size() == size);

            auto equal = [ch](auto c) { return c == ch; };
            assert(etl::all_of(begin(str), end(str), equal));
            return true;
        };

        assert(testCtorChar(1, 'x'));
        assert(testCtorChar(2, 'x'));
        assert(testCtorChar(2, 'x'));
        assert(testCtorChar(3, 'x'));
        assert(testCtorChar(10, 'x'));
        assert(testCtorChar(20, 'x'));
    }

    {
        auto testCtorCharPointerSize = [](char const* s, etl::size_t size) {
            using string_t = T;
            string_t str { s, size };
            assert(!str.full());
            assert(str.capacity() == str.max_size());
            assert(str.size() == size);
            assert(str.length() == size);
            assert(str == etl::string_view { s });
            return true;
        };

        assert(testCtorCharPointerSize("", 0));
        assert(testCtorCharPointerSize("a", 1));
        assert(testCtorCharPointerSize("ab", 2));
        assert(testCtorCharPointerSize("to", 2));
        assert(testCtorCharPointerSize("abc", 3));
        assert(testCtorCharPointerSize("foo_bar", 7));
        assert(testCtorCharPointerSize("foo bar", 7));
        assert(testCtorCharPointerSize("foo?bar", 7));
        assert(testCtorCharPointerSize("foo\nbar", 7));
        assert(testCtorCharPointerSize("xxxxxxxxxx", 10));
    }

    {
        auto testCtorCharPointers = [](char const* s, etl::size_t size) {
            using string_t = T;
            string_t str { s, etl::next(s, static_cast<etl::ptrdiff_t>(size)) };
            assert(!str.full());
            assert(str.capacity() == str.max_size());
            assert(str.size() == size);
            assert(str.length() == size);
            assert(str == etl::string_view { s });
            return true;
        };

        assert(testCtorCharPointers("a", 1));
        assert(testCtorCharPointers("ab", 2));
        assert(testCtorCharPointers("to", 2));
        assert(testCtorCharPointers("abc", 3));
        assert(testCtorCharPointers("foo_bar", 7));
        assert(testCtorCharPointers("foo bar", 7));
        assert(testCtorCharPointers("foo?bar", 7));
        assert(testCtorCharPointers("foo\nbar", 7));
        assert(testCtorCharPointers("xxxxxxxxxx", 10));
    }

    {
        string src { "testabc" };

        string dest1(src, 0, 2);
        assert((dest1 == "te"_sv));

        string dest2(src, 4, 2);
        assert((dest2 == "ab"_sv));

        auto dest3 = string(src, 9, 2);
        assert((dest3 == ""_sv));
    }

    {
        etl::string_view sv { "test" };
        string dest { sv };

        assert(!dest.full());
        assert((dest.size() == etl::size_t(4)));
        assert((dest.length() == etl::size_t(4)));
        assert((dest[0] == 't'));
        assert((dest[1] == 'e'));
        assert((dest[2] == 's'));
        assert((dest[3] == 't'));
    }

    {
        etl::string_view sv { "test" };
        string dest { sv, 2, 2 };

        assert(!dest.full());
        assert((dest.size() == etl::size_t(2)));
        assert((dest.length() == etl::size_t(2)));
        assert((dest[0] == 's'));
        assert((dest[1] == 't'));
    }

    {
        string src1 {};
        string str1 {};
        str1 = src1;
        assert((str1.size() == 0));
        assert((str1.empty()));

        string src2 { "test" };
        string str2 {};
        str2 = src2;
        assert((str2.size() == 4));
        assert((str2 == "test"_sv));

        auto src3 = string { "abc" };
        string str3;
        str3 = src3;
        assert((str3.size() == 3));
        assert((str3 == "abc"_sv));
    }

    {
        auto const* src2 = "test";
        string str2 {};
        str2 = src2;
        assert((str2.size() == 4));
        assert((str2 == "test"_sv));

        auto const* src3 = "abc";
        string str3;
        str3 = src3;
        assert((str3.size() == 3));
        assert((str3 == "abc"_sv));
    }

    {
        auto const src2 = 'a';
        string str2 {};
        str2 = src2;
        assert((str2.size() == 1));
        assert((str2 == "a"_sv));

        auto const src3 = 'b';
        string str3;
        str3 = src3;
        assert((str3.size() == 1));
        assert((str3 == "b"_sv));
    }

    {
        etl::string_view src1 {};
        string str1 {};
        str1 = src1;
        assert((str1.size() == 0));

        etl::string_view src2 { "test" };
        string str2 {};
        str2 = src2;
        assert((str2.size() == 4));
        assert((str2 == "test"_sv));

        auto src3 = "abc"_sv;
        string str3;
        str3 = src3;
        assert((str3.size() == 3));
        assert((str3 == "abc"_sv));
    }

    return true;
}

template <typename T>
[[nodiscard]] constexpr auto test_2() -> bool
{
    using string = T;

    {
        string dest {};

        auto const src1 = string {};
        dest.assign(src1);
        assert((dest.size() == 0));
        assert((dest.empty()));

        auto const src2 = string { "test" };
        dest.assign(src2);
        assert((dest.size() == 4));
        assert((dest == "test"_sv));

        auto src3 = string { "abc" };
        dest.assign(etl::move(src3));
        assert((dest.size() == 3));
        assert((dest == "abc"_sv));

        auto const src4 = string { "abc" };
        dest.assign(src4, 1, 1);
        assert((dest.size() == 1));
        assert((dest == "b"_sv));
    }

    {
        string dest {};

        dest.assign(""_sv);
        assert((dest.size() == 0));
        assert((dest.empty()));

        dest.assign("test"_sv);
        assert((dest.size() == 4));
        assert((dest == "test"_sv));

        dest.assign("abc"_sv);
        assert((dest.size() == 3));
        assert((dest == "abc"_sv));

        dest.assign("abc"_sv, 0);
        assert((dest.size() == 3));
        assert((dest == "abc"_sv));

        dest.assign("abc"_sv, 1);
        assert((dest.size() == 2));
        assert((dest == "bc"_sv));

        dest.assign("abc"_sv, 1, 1);
        assert((dest.size() == 1));
        assert((dest == "b"_sv));

        auto const src = etl::static_string<8> { "abc" };
        dest.assign(src);
        assert((dest.size() == 3));
        assert((dest == "abc"_sv));

        dest.assign(src, 1, 1);
        assert((dest.size() == 1));
        assert((dest == "b"_sv));
    }

    {
        string dest {};

        auto src1 = "test"_sv;
        dest.assign(begin(src1), end(src1));
        assert((dest.size() == 4));
        assert((dest == "test"_sv));

        auto src2 = "abc"_sv;
        dest.assign(begin(src2), end(src2) - 1);
        assert((dest.size() == 2));
        assert((dest == "ab"_sv));
    }

    {
        string dest {};

        dest.assign("test");
        assert((dest.size() == 4));
        assert((dest == "test"_sv));

        dest.assign("abc");
        assert((dest.size() == 3));
        assert((dest == "abc"_sv));
    }

    {
        string dest {};

        dest.assign(1, 'a');
        assert((dest.size() == 1));
        assert((dest == "a"_sv));

        dest.assign(4, 'z');
        assert((dest.size() == 4));
        assert((dest == "zzzz"_sv));
    }

    {
        string str { "abc" };
        assert(str[0] == 'a');
        assert(str[1] == 'b');
        assert(str[2] == 'c');
    }

    {
        string str { "aaa" };

        etl::for_each(str.begin(), str.end(), [](auto& c) { assert(c == char('a')); });
        for (auto const& c : str) { assert(c == char('a')); }
    }

    {
        string str { "aaa" };

        etl::for_each(str.cbegin(), str.cend(), [](auto const& c) { assert(c == char('a')); });
    }

    // TODO: Fix constexpr, fails on gcc-9, but passes gcc-11
    // {
    //     string empty {};
    //     assert((empty.rbegin() == empty.rend()));

    //     string str1 { "test" };
    //     assert((str1.rbegin() != str1.rend()));
    //     auto begin1 = str1.rbegin();
    //     assert((*begin1 == 't'));
    //     begin1++;
    //     assert((*begin1 == 's'));
    //     begin1++;
    //     assert((*begin1 == 'e'));
    //     begin1++;
    //     assert((*begin1 == 't'));
    //     begin1++;
    //     assert((begin1 == str1.rend()));
    // }

    // {
    //     string empty {};
    //     assert((empty.crbegin() == empty.crend()));

    //     string str1 { "test" };
    //     assert((str1.crbegin() != str1.crend()));
    //     auto begin1 = str1.crbegin();
    //     assert((*begin1 == 't'));
    //     begin1++;
    //     assert((*begin1 == 's'));
    //     begin1++;
    //     assert((*begin1 == 'e'));
    //     begin1++;
    //     assert((*begin1 == 't'));
    //     begin1++;
    //     assert((begin1 == str1.crend()));
    // }

    {
        auto str = string();
        str.append(4, 'a');

        assert(str.size() == etl::size_t(4));
        assert(str.length() == etl::size_t(4));
        assert(str[0] == 'a');
        assert(str[1] == 'a');
        assert(str[2] == 'a');
        assert(str[3] == 'a');
    }

    {
        string str {};

        // APPEND 4 CHARACTERS
        char const* cptr = "C-string";
        str.append(cptr, 4);

        assert(str.empty() == false);
        assert(str.capacity() == str.max_size());
        assert(str.size() == etl::size_t(4));
        assert(str.length() == etl::size_t(4));
        assert(str[0] == 'C');
        assert(str[1] == '-');
        assert(str[2] == 's');
        assert(str[3] == 't');
    }

    {
        string str {};
        char const* cptr = "C-string";
        str.append(cptr);

        assert(str[0] == 'C');
        assert(str[1] == '-');
        assert(str[2] == 's');
        assert(str[3] == 't');
    }

    {
        etl::string_view emptySrc { "" };

        string empty {};
        empty.append(begin(emptySrc), end(emptySrc));
        assert((empty.empty()));

        string str { "abc" };
        str.append(begin(emptySrc), end(emptySrc));
        assert((str == "abc"_sv));
    }

    {
        etl::string_view src { "_test" };

        string dest { "abc" };
        dest.append(begin(src), end(src));
        assert((dest == "abc_test"_sv));
    }

    {
        string emptySrc { "" };

        string empty {};
        empty.append(emptySrc);
        assert((empty.empty()));

        string str { "abc" };
        str.append(emptySrc);
        assert((str == "abc"_sv));
    }

    {
        string src { "_test" };

        string dest { "abc" };
        dest.append(src);
        assert((dest == "abc_test"_sv));
    }

    {
        auto str = string { "BCDEF" };

        assert(str.find_first_not_of("ABC") == 2);
        assert(str.find_first_not_of("ABC", 4) == 4);
        assert(str.find_first_not_of('B') == 1);
        assert(str.find_first_not_of('D', 2) == 3);
    }

    {
        auto str = string();
        assert((str == ""));

        str = str + "tes";
        assert((str == "tes"));

        str = str + 't';
        assert((str == "test"));

        str = str + string { "_foo" };
        assert((str == "test_foo"));

        str = "__" + str;
        assert((str == "__test_foo"));

        str = 'a' + str;
        assert((str == "a__test_foo"));
    }

    {
        auto lhs = string();
        auto rhs = string();

        assert((lhs == ""));
        assert((lhs == rhs));
        assert(!(lhs != rhs));
        assert((rhs == lhs));
        assert(!(rhs != lhs));
    }

    {
        auto lhs = string();
        auto rhs = etl::static_string<2> {};

        assert((lhs == ""));
        assert((rhs == ""));
        assert((lhs == rhs));
        assert(!(lhs != rhs));
        assert(!(lhs != ""));
        assert((rhs == lhs));
        assert(!(rhs != lhs));
    }

    {
        assert(!(string {} < ""));
        assert(!(string {} < string {}));
        assert(!(string {} < etl::static_string<2> {}));
        assert(!(etl::static_string<4> {} < string {}));
    }

    {
        assert((string { "abc" } < "def"));
        assert((string { "abc" } < string { "def" }));
        assert((string { "abc" } < string { "defg" }));
    }

    {
        assert(!(string { "def" } < "a"));
        assert(!(string { "def" } < etl::static_string<2> { "a" }));
        assert((etl::static_string<2> { "a" } < string("test")));
    }

    {
        assert((string {} <= ""));
        assert((string {} <= string {}));
        assert((string {} <= etl::static_string<2> {}));
        assert((etl::static_string<4> {} <= string {}));
    }

    {
        assert((string { "abc" } <= "def"));
        assert((string { "abc" } <= string { "def" }));
        assert((string { "abc" } <= string { "defg" }));
        assert((string { "abc" } <= string { "abc" }));
    }

    {
        assert(!(string { "def" } <= "a"));
        assert(!(string { "def" } <= etl::static_string<2> { "a" }));
        assert((etl::static_string<2> { "a" } <= string("test")));
    }

    {
        assert(!(string {} > ""));
        assert(!(string {} > string {}));
        assert(!(string {} > etl::static_string<2> {}));
        assert(!(etl::static_string<4> {} > string {}));
    }

    {
        assert(!(string { "abc" } > "def"));
        assert(!(string { "abc" } > string { "def" }));
        assert(!(string { "abc" } > string { "defg" }));
        assert(!(string { "abc" } > string { "abc" }));
    }

    {
        assert((string { "def" } > etl::static_string<2> { "a" }));
        assert(!(etl::static_string<2> { "a" } > string("test")));
    }

    {
        assert((string {} >= ""));
        assert((string {} >= string {}));
        assert((string {} >= etl::static_string<2> {}));
        assert((etl::static_string<4> {} >= string {}));
    }

    {
        assert((string { "abc" } >= "abc"));
        assert((string { "abc" } >= string { "abc" }));
        assert(!(string { "abc" } >= string { "def" }));
        assert(!(string { "abc" } >= string { "defg" }));
    }

    {
        assert((string { "def" } >= etl::static_string<2> { "a" }));
        assert(!(etl::static_string<2> { "a" } >= string("test")));
    }

    {
        auto str = string();
        assert((str.substr().size() == 0));
        assert((str.substr(1).size() == 0));
        assert((str.substr(10).size() == 0));
    }

    {
        auto str = string("abcd");
        assert((str.size() == 4));
        assert((str.substr(0, 1).size() == 1));
        assert((str.substr(1).size() == 3));
        assert((str.substr(10).size() == 0));
    }

    {
        char destination[32] = {};
        auto str             = string();
        assert((str.empty()));
        assert((str.copy(destination, 0, 0) == 0));
        assert((str.copy(destination, 1, 0) == 0));
        assert((str.copy(destination, 10, 1) == 0));
    }

    {
        char destination[32] = {};
        auto const* src      = "abcd";
        auto str             = string { src };
        assert((str.size() == 4));

        assert((str.copy(destination, 1, 0) == 1));
        assert((destination[0] == 'a'));
        assert((destination[1] == '\0'));

        assert((str.copy(destination, 2, 2) == 2));
        assert((destination[0] == 'c'));
        assert((destination[1] == 'd'));
        assert((destination[2] == '\0'));

        assert((str.copy(destination, str.size()) == 4));
        assert((destination[0] == 'a'));
        assert((destination[1] == 'b'));
        assert((destination[2] == 'c'));
        assert((destination[3] == 'd'));
        assert((destination[4] == '\0'));
    }

    {
        auto lhs = string();
        auto rhs = string();
        assert((lhs.empty()));
        assert((rhs.empty()));

        lhs.swap(rhs);
        assert((lhs.empty()));
        assert((rhs.empty()));
    }

    {
        auto lhs = string { "abc" };
        auto rhs = string { "def" };
        assert((lhs.size() == rhs.size()));

        etl::swap(lhs, rhs);
        assert((lhs.size() == rhs.size()));

        assert((lhs == "def"));
        assert((rhs == "abc"));
    }

    {
        auto lhs = string("foo");
        auto rhs = string { "barbaz" };
        assert((lhs.size() != rhs.size()));

        lhs.swap(rhs);
        assert((lhs.size() != rhs.size()));

        assert((lhs == "barbaz"));
        assert((rhs == "foo"));
    }

    {
        auto lhs = string();
        auto rhs = string();

        assert((lhs.compare(rhs) == 0));
        assert((rhs.compare(lhs) == 0));
    }

    {
        auto lhs = string();
        auto rhs = etl::static_string<2> {};

        assert((lhs.compare(rhs) == 0));
        assert((rhs.compare(lhs) == 0));
    }

    {
        auto const lhs = string("test");
        auto const rhs = string("test");

        assert((lhs.compare("test") == 0));
        assert((lhs.compare("test"_sv) == 0));
        assert((lhs.compare(rhs) == 0));
        assert((rhs.compare(lhs) == 0));

        assert((lhs.compare(1, 1, "test") < 0));
        assert((lhs.compare(1, 1, "test"_sv) < 0));
        assert((lhs.compare(1, 1, rhs) < 0));
        assert((rhs.compare(1, 1, lhs) < 0));

        assert((lhs.compare(1, 1, rhs, 1, 1) == 0));
        assert((rhs.compare(1, 1, lhs, 1, 1) == 0));

        assert((string("te").compare(0, 2, "test"_sv, 0, 2) == 0));
        assert((string("abcabc").compare(3, 3, "abc"_sv, 0, 3) == 0));
        assert((string("abcabc").compare(3, 1, "abc"_sv, 0, 3) < 0));
        assert((string("abcabc").compare(3, 3, "abc"_sv, 0, 1) > 0));

        assert((string("abcabc").compare(3, 3, "abc", 3) == 0));
        assert((string("abcabc").compare(3, 1, "abc", 0, 3) < 0));
        assert((string("abcabc").compare(3, 3, "abc", 0, 1) > 0));
    }

    {
        string emptySrc { "" };

        string empty {};
        empty.append(emptySrc, 0);
        assert((empty.empty()));

        string str { "abc" };
        str.append(emptySrc, 1);
        assert((str == "abc"_sv));
    }

    {
        string src { "_test" };

        string dest { "abc" };
        dest.append(src, 2, 2);
        assert((dest == "abces"_sv));
    }

    {
        etl::string_view emptySrc { "" };

        string empty {};
        empty.append(emptySrc);
        assert((empty.empty()));

        string str { "abc" };
        str.append(emptySrc);
        assert((str == "abc"_sv));
    }

    {
        etl::string_view src { "_test" };

        string dest { "abc" };
        dest.append(src);
        assert((dest == "abc_test"_sv));
    }

    {
        etl::string_view emptySrc {};

        string empty {};
        empty.append(emptySrc, 0);
        assert((empty.empty()));
    }

    {
        etl::string_view src { "_test" };

        string dest { "abc" };
        dest.append(src, 2, 1);
        assert((dest == "abce"_sv));
    }

    {
        string src { "_test" };
        string dest { "abc" };
        dest += src;
        assert((dest == "abc_test"_sv));
    }

    {
        auto src = 'a';
        string dest { "abc" };
        dest += src;
        assert((dest == "abca"_sv));
    }

    {
        auto const* src = "_test";
        string dest { "abc" };
        dest += src;
        assert((dest == "abc_test"_sv));
    }

    {
        etl::string_view src { "_test" };
        string dest { "abc" };
        dest += src;
        assert((dest == "abc_test"_sv));
    }

    {
        // setup
        string str { "aaaaaa" };
        etl::for_each(str.begin(), str.end(), [](auto& c) { c++; });

        // test
        etl::for_each(str.cbegin(), str.cend(), [](auto const& c) { assert(c == 'b'); });

        assert(str.front() == 'b');
        assert(str.back() == 'b');
    }

    {
        string str { "junk" };
        assert((str.front() == 'j'));
        assert((etl::as_const(str).front() == 'j'));

        assert((str.back() == 'k'));
        assert((etl::as_const(str).back() == 'k'));
    }

    {
        string str { "junk" };
        assert((str.data() == str.c_str()));
        assert((str.c_str() != nullptr));
        assert((str.c_str()[0] == 'j'));
    }

    {
        string str { "junk" };
        auto sv = etl::string_view { str };
        assert((sv.data()[0] == 'j'));
    }

    {
        // setup
        string str { "junk" };
        assert(str.empty() == false);

        // test
        str.clear();
        assert(str.capacity() == str.max_size());
        assert(str.empty() == true);
        assert(str.size() == etl::size_t(0));
    }

    {
        string str { "" };
        str.push_back('a');
        str.push_back('b');
        assert(str == string("ab"));
        assert(str.size() == 2);
    }

    {
        string str { "abc" };
        str.pop_back();
        str.pop_back();
        assert(str == string("a"));
        assert(str == "a");
        assert(str.size() == 1);
    }

    {
        auto str = string();
        str.insert(0, 4, 'a');
        assert((str.size() == 4));
        assert((str == "aaaa"_sv));
    }

    {
        auto str = string("test");
        str.insert(0, 4, 'a');
        assert((str.size() == 8));
        assert((str == "aaaatest"_sv));

        str = string("test");
        str.insert(1, 2, 'a');
        str.insert(0, 1, 'b');
        assert((str.size() == 7));
        assert((str == "btaaest"_sv));

        str = string("test");
        str.insert(str.size(), 2, 'a');
        assert((str.size() == 6));
        assert((str == "testaa"_sv));
    }

    {
        auto str = string("");
        str.insert(0, str.capacity(), 'a');
        assert((str.full()));
        assert((str.size() == str.capacity()));
        assert((etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; })));
    }

    {
        auto str = string();
        str.insert(0, "aaaa");
        assert((str.size() == 4));
        assert((str == "aaaa"_sv));
    }

    {
        auto str = string("test");
        str.insert(0, "abcd");
        assert((str.size() == 8));
        assert((str == "abcdtest"_sv));

        str = string("test");
        str.insert(1, "aa");
        str.insert(0, "b");
        assert((str.size() == 7));
        assert((str == "btaaest"_sv));

        str = string("test");
        str.insert(str.size(), "aa");
        assert((str.size() == 6));
        assert((str == "testaa"_sv));
    }

    {
        auto str = string("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) { str.insert(0, "a"); }

        assert((str.full()));
        assert((str.size() == str.capacity()));
        assert((etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; })));
    }

    {
        auto str = string();
        str.insert(0, "aaaa", 4);
        assert((str.size() == 4));
        assert((str == "aaaa"_sv));
    }

    {
        auto str = string("test");
        str.insert(0, "abcd", 3);
        assert((str.size() == 7));
        assert((str == "abctest"_sv));

        str = string("test");
        str.insert(1, "aa", 2);
        str.insert(0, "b", 1);
        assert((str.size() == 7));
        assert((str == "btaaest"_sv));

        str = string("test");
        str.insert(str.size(), "aa", 1);
        assert((str.size() == 5));
        assert((str == "testa"_sv));
    }

    {
        auto str = string("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) { str.insert(0, "ab", 1); }

        assert((str.full()));
        assert((str.size() == str.capacity()));
        assert((etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; })));
    }

    {
        string str = "This is an example";

        // Erase "This "
        str.erase(0, 5);
        assert((str == "is an example"_sv));

        // Erase ' '
        assert((*str.erase(etl::find(begin(str), end(str), ' ')) == 'a'));
        assert((str == "isan example"_sv));

        // Trim from ' ' to the end of the string
        str.erase(str.find(' '));
        assert((str == "isan"_sv));
    }

    {
        auto str = string();
        assert((str.empty() == true));

        // grow
        str.resize(2);
        assert((str.empty() == false));
        assert((str.size() == 2));
        assert((str[0] == '\0'));
        assert((str[1] == '\0'));

        // shrink
        str.resize(1);
        assert((str.empty() == false));
        assert((str.size() == 1));
        assert((str[0] == '\0'));
    }

    {
        auto str = string();
        assert((str.empty() == true));

        // grow
        str.resize(2, 'a');
        assert((str.empty() == false));
        assert((str.size() == 2));
        assert((str[0] == 'a'));
        assert((str[1] == 'a'));

        // shrink
        str.resize(1, 'a');
        assert((str.empty() == false));
        assert((str.size() == 1));
        assert((str[0] == 'a'));
    }

    {
        auto str = string();
        assert(!(str.starts_with("foo"_sv)));
        assert(!(str.starts_with("foo")));
        assert(!(str.starts_with('f')));
    }

    {
        auto str = string("test");
        assert(!(str.starts_with("foo"_sv)));
        assert(!(str.starts_with("foo")));
        assert(!(str.starts_with('f')));
    }

    {
        auto str1 = string("foo");
        assert((str1.starts_with("foo"_sv)));
        assert((str1.starts_with("foo")));
        assert((str1.starts_with('f')));

        auto str2 = string { "foobar" };
        assert((str2.starts_with("foo"_sv)));
        assert((str2.starts_with("foo")));
        assert((str2.starts_with('f')));
    }

    {
        auto str = string();
        assert(!(str.ends_with("foo"_sv)));
        assert(!(str.ends_with("foo")));
        assert(!(str.ends_with('o')));
    }

    {
        auto str = string("test");
        assert(!(str.ends_with("foo"_sv)));
        assert(!(str.ends_with("foo")));
        assert(!(str.ends_with('o')));
    }

    {
        auto str = string("foo");
        assert((str.ends_with("foo"_sv)));
        assert((str.ends_with("foo")));
        assert((str.ends_with('o')));

        auto str2 = string("barfoo");
        assert((str2.ends_with("foo"_sv)));
        assert((str2.ends_with("foo")));
        assert((str2.ends_with('o')));
    }

    {
        using string_t = string;

        auto s = string_t("0123456");
        assert((s.replace(0, 2, string_t("xx")) == "xx23456"_sv));
        assert((s.replace(2, 1, string_t("xx")) == "xxx3456"_sv));
        assert((s.replace(begin(s) + 3, begin(s) + 4, string_t("x"))) == "xxxx456"_sv);
    }

    {
        auto const lhs = string("test");
        auto const rhs = string("te");

        assert((lhs.compare(rhs) > 0));
        assert((rhs.compare("test"_sv) < 0));

        auto other = etl::static_string<9> { "te" };
        assert((lhs.compare(other) > 0));
        assert((other.compare(etl::string_view("te")) == 0));
    }

    {
        auto str = string();
        assert((str.find(string(), 0) == 0));
        assert((str.find(string(), 1) == string::npos));
        assert((str.find(string { "" }) == 0));
    }

    {
        auto str = string { "def" };
        assert((str.find(string { "abc" }, 0) == string::npos));
        assert((str.find(string { "abc" }, 1) == string::npos));
        assert((str.find(string { "abc" }) == string::npos));
    }

    {
        auto str = string("abcd");
        assert((str.find(string { "abc" }, 0) == 0));
        assert((str.find(string { "bc" }, 1) == 1));
        assert((str.find(string { "cd" }) == 2));
    }

    {
        auto str = string();
        assert((str.find("") == 0));
        assert((str.find("", 0) == 0));
        assert((str.find("", 1) == string::npos));
    }

    {
        auto str = string { "def" };
        assert((str.find("abc", 0) == string::npos));
        assert((str.find("abc", 1) == string::npos));
        assert((str.find("abc") == string::npos));
    }

    {
        auto str = string("abcd");
        assert((str.find("abc", 0) == 0));
        assert((str.find("bc", 1) == 1));
        assert((str.find("cd") == 2));
    }

    {
        auto str = string();
        assert((str.find('a', 0) == string::npos));
        assert((str.find('a', 1) == string::npos));
        assert((str.find('a') == string::npos));
    }

    {
        auto str = string { "bcdef" };
        assert((str.find('a', 0) == string::npos));
        assert((str.find('a', 1) == string::npos));
        assert((str.find('a') == string::npos));
    }

    {
        auto str = string("abcd");
        assert((str.find('a', 0) == 0));
        assert((str.find('b', 1) == 1));
        assert((str.find('c') == 2));
    }

    {
        auto str = string("test");
        assert((str.rfind(string()) == 0));
        assert((str.rfind(string(), 0) == 0));
        assert((str.rfind(string(), string::npos) == str.size()));
    }

    {
        auto str = string { "def" };
        assert((str.rfind(string { "abc" }, 0) == string::npos));
        assert((str.rfind(string { "abc" }, 1) == string::npos));
        assert((str.rfind(string { "abc" }) == string::npos));
    }

    {
        // auto const str = string ("test");
        // assert((str.rfind(string {"t"}) == 3));
        // assert((str.rfind(string {"est"}) == 1));

        // assert((str.rfind(string {"st"}, 12) == 2));
        // assert((str.rfind(string {"st"}, 12) == 2));
    }

    {
        auto str = string("test");
        assert((str.rfind("") == 0));
        assert((str.rfind("", 0) == 0));
        assert((str.rfind("", string::npos) == str.size()));
    }

    {
        auto str = string { "def" };
        assert((str.rfind("abc", 0) == string::npos));
        assert((str.rfind("abc", 1) == string::npos));
        assert((str.rfind("abc") == string::npos));
    }

    {
        auto const str = string("test");
        assert((str.rfind("t") == 0));
        // assert((str.rfind("t", 1) == 3));
        // assert((str.rfind("est") == 1));

        // assert((str.rfind("st", 12) == 2));
        // assert((str.rfind("st", 12) == 2));
    }

    {
        auto str = string();
        assert((str.find_first_of(string(), 0) == string::npos));
        assert((str.find_first_of(string(), 1) == string::npos));
        assert((str.find_first_of(string { "" }) == string::npos));
    }

    {
        auto str = string { "def" };
        assert((str.find_first_of(string { "abc" }, 0) == string::npos));
        assert((str.find_first_of(string { "abc" }, 1) == string::npos));
        assert((str.find_first_of(string { "abc" }) == string::npos));
    }

    {
        auto str = string("abcd");
        assert((str.find_first_of(string { "abc" }, 0) == 0));
        assert((str.find_first_of(string { "bc" }, 1) == 1));
        assert((str.find_first_of(string { "cd" }) == 2));
    }

    {
        auto str = string();
        assert((str.find_first_of("", 0) == string::npos));
        assert((str.find_first_of("", 1) == string::npos));
        assert((str.find_first_of("") == string::npos));
    }

    {
        auto str = string { "def" };
        assert((str.find_first_of("abc", 0) == string::npos));
        assert((str.find_first_of("abc", 1) == string::npos));
        assert((str.find_first_of("abc") == string::npos));
    }

    {
        auto str = string("abcd");
        assert((str.find_first_of("abc", 0) == 0));
        assert((str.find_first_of("bc", 1) == 1));
        assert((str.find_first_of("cd") == 2));
    }

    {
        auto str = string();
        assert((str.find_first_of(""_sv, 0) == string::npos));
        assert((str.find_first_of(""_sv, 1) == string::npos));
        assert((str.find_first_of(""_sv) == string::npos));
    }

    {
        auto str = string { "def" };
        assert((str.find_first_of("abc"_sv, 0) == string::npos));
        assert((str.find_first_of("abc"_sv, 1) == string::npos));
        assert((str.find_first_of("abc"_sv) == string::npos));
    }

    {
        auto str = string("abcd");
        assert((str.find_first_of("abc"_sv, 0) == 0));
        assert((str.find_first_of("bc"_sv, 1) == 1));
        assert((str.find_first_of("cd"_sv) == 2));
    }

    {
        auto str = string();
        assert((str.find_first_of('a', 0) == string::npos));
        assert((str.find_first_of('a', 1) == string::npos));
        assert((str.find_first_of('a') == string::npos));
    }

    {
        auto str = string { "def" };
        assert((str.find_first_of('a', 0) == string::npos));
        assert((str.find_first_of('a', 1) == string::npos));
        assert((str.find_first_of('a') == string::npos));
    }

    {
        auto str = string("abcd");
        assert((str.find_first_of('a', 0) == 0));
        assert((str.find_first_of('b', 1) == 1));
        assert((str.find_first_of('c') == 2));
    }

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    assert(sizeof(etl::static_string<6>) == 7);   // tiny storage, size_type = uint8
    assert(sizeof(etl::static_string<7>) == 8);   // tiny storage, size_type = uint8
    assert(sizeof(etl::static_string<16>) == 18); // normal storage, size_type = uint8

    assert(test_1<etl::static_string<24>>());
    assert(test_1<etl::static_string<55>>());
    assert(test_1<etl::static_string<64>>());
    assert(test_1<etl::static_string<256>>());

    assert(test_2<etl::static_string<24>>());
    // assert(test_2<etl::static_string<55>>());
    // assert(test_2<etl::static_string<64>>());
    // assert(test_2<etl::static_string<256>>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}

// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/algorithm.hpp>
#include <etl/string_view.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
[[nodiscard]] constexpr static auto test_constructor() -> bool
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
[[nodiscard]] constexpr static auto test_assign() -> bool
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

    return true;
}

[[nodiscard]] constexpr static auto test_all() -> bool
{
    CHECK(sizeof(etl::inplace_string<6>) == 7);   // tiny storage, size_type = uint8
    CHECK(sizeof(etl::inplace_string<7>) == 8);   // tiny storage, size_type = uint8
    CHECK(sizeof(etl::inplace_string<16>) == 18); // normal storage, size_type = uint8

    CHECK(test_constructor<etl::inplace_string<22>>());
    CHECK(test_constructor<etl::inplace_string<31>>());

    CHECK(test_assign<etl::inplace_string<22>>());
    CHECK(test_assign<etl::inplace_string<31>>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

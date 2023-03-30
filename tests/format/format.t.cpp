// SPDX-License-Identifier: BSL-1.0

#include "etl/format.hpp"

#include "etl/iterator.hpp"
#include "etl/string.hpp"
#include "etl/string_view.hpp"

#include "testing/testing.hpp"

using namespace etl::string_view_literals;
using etl::string_view;

template <typename T>
auto test_ints() -> bool
{
    // auto test = [](T in, auto expected) -> bool {
    //     using string_t = etl::static_string<32>;
    //     auto str       = string_t();
    //     auto ctx       = etl::format_context<string_t> { etl::back_inserter(str) };
    //     auto formatter = etl::formatter<T, char> {};
    //     formatter.format(in, ctx);
    //     assert(str == expected);
    //     return true;
    // };

    //     assert(test(T(0), "0"));
    //     assert(test(T(1), "1"));
    //     assert(test(T(2), "2"));
    //     assert(test(T(3), "3"));
    //     assert(test(T(4), "4"));
    //     assert(test(T(5), "5"));
    //     assert(test(T(6), "6"));
    //     assert(test(T(7), "7"));
    //     assert(test(T(8), "8"));
    //     assert(test(T(9), "9"));
    //     assert(test(T(10), "10"));
    //     assert(test(T(11), "11"));
    //     assert(test(T(99), "99"));
    //     assert(test(T(111), "111"));
    //     assert(test(T(1234), "1234"));
    //     assert(test(T(9999), "9999"));
    return true;
}

static auto test_all() -> bool
{

    //     assert(test_ints<short>());
    //     assert(test_ints<int>());
    //     assert(test_ints<long>());
    //     assert(test_ints<long long>());
    //     assert(test_ints<unsigned short>());
    //     assert(test_ints<unsigned int>());
    //     assert(test_ints<unsigned long>());
    //     assert(test_ints<unsigned long long>());

    //     // no arg
    //     {
    //         auto str    = etl::static_string<32> {};
    //         auto target = string_view("test");
    //         etl::format_to(etl::back_inserter(str), "test");
    //         assert(string_view(str) == target);
    //     }

    //     // no arg escaped
    //     {
    //         auto str1 = etl::static_string<32> {};
    //         etl::format_to(etl::back_inserter(str1), "{{test}}");
    //         assert(string_view(str1) == string_view("{test}"));

    //         auto str2 = etl::static_string<32> {};
    //         etl::format_to(etl::back_inserter(str2), "{{abc}} {{def}}");
    //         assert(string_view(str2) == string_view("{abc} {def}"));
    //     }

    //     // single arg
    //     {
    //         auto str    = etl::static_string<32> {};
    //         auto target = string_view("test");
    //         etl::format_to(etl::back_inserter(str), "tes{}", 't');
    //         assert(string_view(str) == target);
    //     }

    //     // escape single arg
    //     {
    //         auto str1 = etl::static_string<32> {};
    //         etl::format_to(etl::back_inserter(str1), "{} {{test}}", 'a');
    //         assert(string_view(str1) == string_view("a {test}"));

    //         // auto str2 = etl::static_string<32> {};
    //         // etl::format_to(etl::back_inserter(str2), "{{test}} {}", 'b');
    //         // assert(string_view(str2.data()) == string_view("{test} b"));
    //     }

    //     // replace multiple args
    //     {
    //         auto str1 = etl::static_string<32> {};
    //         etl::format_to(etl::back_inserter(str1), "{} {} {}", 'a', 'b', 'c');
    //         assert(string_view(str1) == string_view("a b c"));

    //         auto str2 = etl::static_string<32> {};
    //         auto fmt2 = string_view("some {} text {} mixed {}");
    //         etl::format_to(etl::back_inserter(str2), fmt2, 'a', 'b', 'c');
    //         assert(string_view(str2) == string_view("some a text b mixed c"));
    //     }

    //     // single arg
    //     {
    //         auto str    = etl::static_string<32> {};
    //         auto target = string_view("testtt");
    //         etl::format_to(etl::back_inserter(str), "tes{}", "ttt");
    //         assert(string_view(str.begin()) == target);
    //     }

    //     // // escape single arg
    //     // {
    //     //     auto str1 = etl::static_string<32> {};
    //     //     etl::format_to(etl::back_inserter(str1), "{} {{test}}", "abc");
    //     //     assert(string_view(str1.begin()) == string_view("abc {test}"));

    //     //     auto str2 = etl::static_string<32> {};
    //     //     etl::format_to(etl::back_inserter(str2), "{{test}} {}", "abc");
    //     //     assert(string_view(str2.begin()) == string_view("{test} abc"));
    //     // }

    //     // escape
    //     {
    //         auto b        = etl::static_string<32> {};
    //         auto target   = string_view("{abc}");
    //         auto const sz = static_cast<etl::ptrdiff_t>(b.size());
    //         auto r        = etl::format_to_n(b.data(), sz, "{{abc}}");
    //         assert(r.out == b.begin() + target.size());
    //         assert(r.size == static_cast<decltype(r.size)>(target.size()));
    //         assert(string_view(b.begin()) == target);
    //     }

    //     // replace single arg
    //     {
    //         auto b        = etl::static_string<32> {};
    //         auto target   = string_view("test");
    //         auto const sz = static_cast<etl::ptrdiff_t>(b.size());
    //         auto r        = etl::format_to_n(data(b), sz, "tes{}", 't');
    //         assert(r.out == b.begin() + target.size());
    //         assert(r.size == static_cast<decltype(r.size)>(target.size()));
    //         assert(string_view(b.begin()) == target);
    //     }

    //     // replace multiple args
    //     // {
    //     //     auto b      = etl::static_string<32> {};
    //     //     auto fmt    = string_view("{} {}");
    //     //     auto target = string_view("a b");
    //     //     auto r      = etl::format_to_n(data(b), size(b), fmt, 'a', 'b');
    //     //     assert(r.out == b.begin() + target.size());
    //     //     assert(r.size == static_cast<decltype(r.size)>(target.size()));
    //     //     assert(string_view(b.begin()) == target);
    //     // }

    //     // argument only
    //     {
    //         auto slices = etl::detail::split_at_next_argument("{}");
    //         assert(slices.first == ""_sv);
    //         assert(slices.second == ""_sv);
    //     }

    //     // prefix
    //     {
    //         auto slices = etl::detail::split_at_next_argument("a{}");
    //         assert(slices.first == "a"_sv);
    //         assert(slices.second == ""_sv);
    //     }

    //     // postfix
    //     {
    //         auto slices = etl::detail::split_at_next_argument("{}b");
    //         assert(slices.first == ""_sv);
    //         assert(slices.second == "b"_sv);
    //     }

    //     // pre&postfix
    //     {
    //         auto slices = etl::detail::split_at_next_argument("ab{}cd");
    //         assert(slices.first == "ab"_sv);
    //         assert(slices.second == "cd"_sv);
    //     }

    //     // escape
    //     {
    //         auto slices = etl::detail::split_at_next_argument("{{test}}");
    //         assert(slices.first == "{{test}}"_sv);
    //         assert(slices.second == ""_sv);
    //     }

    //     using string_t = etl::static_string<32>;

    //     // none
    //     {
    //         auto str = string_t {};
    //         auto ctx = etl::format_context<string_t> { etl::back_inserter(str) };
    //         etl::detail::format_escaped_sequences("test", ctx);
    //         assert(string_view(str) == "test"_sv);
    //     }

    //     // single
    //     {
    //         auto str = string_t {};
    //         auto ctx = etl::format_context<string_t> { etl::back_inserter(str) };
    //         etl::detail::format_escaped_sequences("{{test}}", ctx);
    //         assert(string_view(str) == "{test}"_sv);
    //     }

    //     // single with noise
    //     {
    //         auto str1 = string_t {};
    //         auto ctx1 = etl::format_context<string_t> { etl::back_inserter(str1) };
    //         etl::detail::format_escaped_sequences("foobar {{test}}", ctx1);
    //         assert(string_view(str1) == "foobar {test}"_sv);

    //         auto str2 = string_t {};
    //         auto ctx2 = etl::format_context<string_t> { etl::back_inserter(str2) };
    //         etl::detail::format_escaped_sequences("foobar__{{test}}", ctx2);
    //         assert(string_view(str2) == "foobar__{test}"_sv);

    //         auto str3 = string_t {};
    //         auto ctx3 = etl::format_context<string_t> { etl::back_inserter(str3) };
    //         etl::detail::format_escaped_sequences("{{test}} foobar", ctx3);
    //         assert(string_view(str3) == "{test} foobar"_sv);

    //         auto str4 = string_t {};
    //         auto ctx4 = etl::format_context<string_t> { etl::back_inserter(str4) };
    //         etl::detail::format_escaped_sequences("{{test}}__foobar", ctx4);
    //         assert(string_view(str4) == "{test}__foobar"_sv);
    //     }

    //     // multiple
    //     {
    //         auto str1 = string_t {};
    //         auto ctx1 = etl::format_context<string_t> { etl::back_inserter(str1) };
    //         etl::detail::format_escaped_sequences("{{test}} {{abc}}", ctx1);
    //         assert(string_view(str1) == "{test} {abc}"_sv);

    //         auto str2 = string_t {};
    //         auto ctx2 = etl::format_context<string_t> { etl::back_inserter(str2) };
    //         etl::detail::format_escaped_sequences("{{test}}{{abc}}", ctx2);
    //         assert(string_view(str2) == "{test}{abc}"_sv);
    //     }

    return true;
}

auto main() -> int
{
    assert(test_all());

    // TODO: Doesn't work on gcc-9 & clang-10, but works on gcc-11 & clang-13
    // static_assert(test_all());

    return 0;
}

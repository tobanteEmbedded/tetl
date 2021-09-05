/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/string_view.hpp"

#include "etl/string.hpp"

#include "testing/testing.hpp"

using etl::string_view;
using namespace etl::literals;

constexpr auto test() -> bool
{
    {
        assert(string_view {}.data() == nullptr);
        assert(string_view {}.size() == 0);
        assert(string_view {}.length() == 0);
    }

    {
        auto const sv1 = string_view {};
        auto const sv2 = sv1;

        assert(sv2.data() == nullptr);
        assert(sv2.size() == 0);
        assert(sv2.length() == 0);
    }

    {
        auto const sv1 = "test"_sv;
        auto const sv2 = sv1;

        assert(sv2.data() != nullptr);
        assert(sv2.size() == 4);
        assert(sv2.length() == 4);
    }

    {
        auto const sv = string_view {};
        assert(sv.data() == nullptr);
        assert(sv.begin() == sv.cbegin());
    }

    {
        auto const sv = "test"_sv;
        assert(*sv.begin() == 't');
        assert(sv.begin() == sv.cbegin());
    }

    {
        auto const sv = string_view {};
        assert(sv.data() == nullptr);
        assert(sv.end() == sv.cend());
    }

    {
        auto const sv = "test"_sv;
        assert(sv.end() == sv.begin() + 4);
        assert(sv.end() == sv.cend());
    }

    {
        auto const sv = string_view {};
        assert(sv.data() == nullptr);
        assert(sv.rend() == sv.crend());
        assert(sv.data() == nullptr);
        assert(sv.rbegin() == sv.crbegin());
    }

    {
        auto const sv = "abc"_sv;
        assert(*sv.rbegin() == 'c');
        assert(sv.rbegin() == sv.crbegin());
        assert(sv.rend() != sv.rbegin());
        assert(sv.rend() == sv.crend());
    }

    {
        auto const sv = "test"_sv;
        auto counter  = string_view::size_type { 0 };
        for (auto c : sv) {
            etl::ignore_unused(c);
            counter++;
        }

        assert(counter == sv.size());
        assert(counter == 4);
    }
    {
        auto const sv1 = "test"_sv;
        assert(sv1[0] == 't');
        assert(sv1[1] == 'e');
        assert(sv1[2] == 's');
        assert(sv1[3] == 't');

        auto sv2 = string_view { "tobi" };
        assert(sv2[0] == 't');
        assert(sv2[1] == 'o');
        assert(sv2[2] == 'b');
        assert(sv2[3] == 'i');
    }

    {
        auto const sv1 = "test"_sv;
        assert(sv1.front() == 't');

        auto sv2 = "abc"_sv;
        assert(sv2.front() == 'a');
    }
    {
        auto const sv1 = "test"_sv;
        assert(sv1.back() == 't');

        auto sv2 = "abc"_sv;
        assert(sv2.back() == 'c');
    }
    {
        auto const sv = "test"_sv;
        assert(sv.max_size() == string_view::size_type(-1));
    }

    {
        auto const t = string_view {};
        assert(t.empty());

        auto const f = "test"_sv;
        assert(!f.empty());
    }

    {
        auto sv = string_view {};
        assert((sv.empty()));
        sv.remove_prefix(0);
        assert((sv.empty()));
    }

    {
        auto sv = "test"_sv;
        assert((sv.size() == 4));
        sv.remove_prefix(1);
        assert((sv.size() == 3));
        assert((sv[0] == 'e'));
    }

    {
        auto sv = string_view {};
        assert((sv.empty()));
        sv.remove_suffix(0);
        assert((sv.empty()));
    }

    {
        auto sv = "test"_sv;
        assert((sv.size() == 4));

        sv.remove_suffix(1);
        assert((sv.size() == 3));
        assert((sv[0] == 't'));
        assert((sv[1] == 'e'));
        assert((sv[2] == 's'));

        sv.remove_suffix(2);
        assert((sv.size() == 1));
        assert((sv[0] == 't'));
    }

    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        assert((sv.copy(&buffer[0], 2, 0) == 2));
        assert((buffer[0] == 't'));
        assert((buffer[1] == 'e'));
        assert((buffer[2] == 0));
        assert((buffer[3] == 0));
    }

    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        assert((sv.copy(&buffer[0], 2, 1) == 2));
        assert((buffer[0] == 'e'));
        assert((buffer[1] == 's'));
        assert((buffer[2] == 0));
        assert((buffer[3] == 0));
    }

    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        assert((sv.copy(&buffer[0], 2, 3) == 1));
        assert((buffer[0] == 't'));
        assert((buffer[1] == 0));
        assert((buffer[2] == 0));
        assert((buffer[3] == 0));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.starts_with("t"_sv)));
        assert((sv.starts_with(string_view { "te" })));
        assert((sv.starts_with(string_view { "tes" })));
        assert((sv.starts_with("test"_sv)));
    }

    {
        auto const sv = "abc"_sv;
        assert((sv.starts_with('a')));
    }

    {
        auto const sv = "abc"_sv;
        assert((sv.starts_with("a")));
        assert((sv.starts_with("ab")));
        assert((sv.starts_with("abc")));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.ends_with("t"_sv)));
        assert((sv.ends_with("st"_sv)));
        assert((sv.ends_with("est"_sv)));
        assert((sv.ends_with("test"_sv)));
    }

    {
        auto const sv = "abc"_sv;
        assert((sv.ends_with('c')));
        assert(!(sv.ends_with('a')));
    }

    {
        auto const sv = "abc"_sv;
        assert((sv.ends_with("c")));
        assert((sv.ends_with("bc")));
        assert((sv.ends_with("abc")));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find("t"_sv) == 0));
        assert((sv.find("est"_sv) == 1));

        assert((sv.find("st"_sv, 1) == 2));
        assert((sv.find("st"_sv, 2) == 2));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find('t') == 0));
        assert((sv.find('e') == 1));

        assert((sv.find('s') == 2));
        assert((sv.find('s', 2) == 2));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find("t", 0, 1) == 0));
        assert((sv.find("est", 0, 3) == 1));

        assert((sv.find("x", 0, 1) == string_view::npos));
        assert((sv.find("foo", 0, 3) == string_view::npos));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find("t", 0) == 0));
        assert((sv.find("est", 0) == 1));

        assert((sv.find("x", 0) == string_view::npos));
        assert((sv.find("foo", 0) == string_view::npos));

        assert((sv.find("xxxxx", 0) == string_view::npos));
        assert((sv.find("foobarbaz", 0) == string_view::npos));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.rfind("t"_sv) == 3));
        assert((sv.rfind("est"_sv) == 1));

        assert((sv.rfind("st"_sv, 12) == 2));
        assert((sv.rfind("st"_sv, 12) == 2));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.rfind('t') == 3));
        assert((sv.rfind('e') == 1));

        assert((sv.rfind('s') == 2));
        assert((sv.rfind('s', 2) == 2));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.rfind("t", string_view::npos, 1) == 3));
        assert((sv.rfind("est", string_view::npos, 3) == 1));

        assert((sv.rfind("x", string_view::npos, 1) == string_view::npos));
        assert((sv.rfind("foo", string_view::npos, 3) == string_view::npos));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.rfind("t", string_view::npos) == 3));
        assert((sv.rfind("est", string_view::npos) == 1));

        assert((sv.rfind("x", 0) == string_view::npos));
        assert((sv.rfind("foo", 0) == string_view::npos));

        assert((sv.rfind("xxxxx", 0) == string_view::npos));
        assert((sv.rfind("foobarbaz", 0) == string_view::npos));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find_first_of("t"_sv) == 0));
        assert((sv.find_first_of("est"_sv) == 0));

        assert((sv.find_first_of("t"_sv, 1) == 3));
        assert((sv.find_first_of("st"_sv, 2) == 2));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find_first_of('t') == 0));
        assert((sv.find_first_of('e') == 1));

        assert((sv.find_first_of('t', 1) == 3));
        assert((sv.find_first_of('s') == 2));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find_first_of("t", 0, 1) == 0));
        assert((sv.find_first_of("est", 0, 3) == 0));

        assert((sv.find_first_of("x", 0, 1) == string_view::npos));
        assert((sv.find_first_of("foo", 0, 3) == string_view::npos));
    }

    {
        auto const sv = "test"_sv;
        assert((sv.find_first_of("t", 1) == 3));
        assert((sv.find_first_of("est", 1) == 1));

        assert((sv.find_first_of("x", 0) == string_view::npos));
        assert((sv.find_first_of("foo", 0) == string_view::npos));

        assert((sv.find_first_of("xxxxx", 0) == string_view::npos));
        assert((sv.find_first_of("foobarbaz", 0) == string_view::npos));
    }

    {
        assert("BCDEF"_sv.find_first_not_of("ABC") == 2);
        assert("BCDEF"_sv.find_first_not_of("ABC", 4) == 4);
        assert("BCDEF"_sv.find_first_not_of('B') == 1);
        assert("BCDEF"_sv.find_first_not_of('D', 2) == 3);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.find_last_of("t"_sv) == 3);
        assert(sv.find_last_of("est"_sv) == 3);

        assert(sv.find_last_of("t"_sv, 1) == 0);
        assert(sv.find_last_of("st"_sv, 2) == 2);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.find_last_of('t') == 3);
        assert(sv.find_last_of('e') == 1);
        assert(sv.find_last_of('s') == 2);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.find_last_of("t", 12, 1) == 3);
        assert(sv.find_last_of("es", 12, 2) == 2);

        assert(sv.find_last_of("x", 0, 1) == etl::string_view::npos);
        assert(sv.find_last_of("foo", 0, 3) == etl::string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.find_last_of("t") == 3);
        assert(sv.find_last_of("es") == 2);

        assert(sv.find_last_of("x") == etl::string_view::npos);
        assert(sv.find_last_of("foo") == etl::string_view::npos);

        assert(sv.find_last_of("xxxxx") == etl::string_view::npos);
        assert(sv.find_last_of("foobarbaz") == etl::string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.find_last_not_of("t"_sv) == 2);
        assert(sv.find_last_not_of("est"_sv) == sv.npos);
        assert(sv.find_last_not_of(etl::string_view { "s" }, 2) == 1);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.find_last_not_of('t') == 2);
        assert(sv.find_last_not_of('e') == 3);
        assert(sv.find_last_not_of('s') == 3);
    }

    {
        auto const npos = etl::string_view::npos;
        auto const sv   = "test"_sv;
        assert(sv.find_last_not_of("t", npos, 1) == 2);
        assert(sv.find_last_not_of("es", npos, 2) == 3);
        assert(sv.find_last_not_of("est", npos, 4) == npos);
        assert(sv.find_last_not_of("tes", npos, 4) == npos);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.find_last_not_of("t") == 2);
        assert(sv.find_last_not_of("es") == 3);

        assert(sv.find_last_not_of("tes") == etl::string_view::npos);
        assert(sv.find_last_not_of("est") == etl::string_view::npos);
    }

    {
        auto const sv = "test"_sv;

        auto const sub1 = sv.substr(0, 1);
        assert(sub1.size() == 1);
        assert(sub1[0] == 't');

        auto const sub2 = sv.substr(0, 2);
        assert(sub2.size() == 2);
        assert(sub2[0] == 't');
        assert(sub2[1] == 'e');

        auto const sub3 = sv.substr(2, 2);
        assert(sub3.size() == 2);
        assert(sub3[0] == 's');
        assert(sub3[1] == 't');
    }

    {
        auto lhs = etl::string_view();
        auto rhs = etl::string_view();

        assert(lhs.compare(rhs) == 0);
        assert(rhs.compare(lhs) == 0);
    }

    {
        auto const lhs = "test"_sv;
        auto const rhs = "test"_sv;

        assert(lhs.compare("test") == 0);
        assert(lhs.compare("test"_sv) == 0);
        assert(lhs.compare(rhs) == 0);
        assert(rhs.compare(lhs) == 0);

        assert(lhs.compare(1, 1, "test") < 0);
        assert(lhs.compare(1, 1, "test"_sv) < 0);
        assert(lhs.compare(1, 1, rhs) < 0);
        assert(rhs.compare(1, 1, lhs) < 0);

        assert(lhs.compare(1, 1, rhs, 1, 1) == 0);
        assert(rhs.compare(1, 1, lhs, 1, 1) == 0);

        assert("te"_sv.compare(0, 2, "test"_sv, 0, 2) == 0);
        assert("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 3) == 0);
        assert("abcabc"_sv.compare(3, 1, "abc"_sv, 0, 3) < 0);
        assert("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 1) > 0);

        assert("abcabc"_sv.compare(3, 3, "abc", 3) == 0);
        assert("abcabc"_sv.compare(3, 1, "abc", 0, 3) < 0);
        assert("abcabc"_sv.compare(3, 3, "abc", 0, 1) > 0);
    }

    {
        auto const lhs = "test"_sv;
        auto const rhs = "te"_sv;

        assert(lhs.compare(rhs) > 0);
        assert(rhs.compare("test"_sv) < 0);
    }

    {
        auto const sv  = "test"_sv;
        auto const str = etl::static_string<16> { "test" };
        assert(!(sv < sv));
        assert(etl::string_view { "" } < sv);
        assert(sv.substr(0, 1) < sv);
        assert("abc"_sv < sv);
        assert(!(sv < str));
        assert(!(str < sv));
    }

    {
        auto const sv = "test"_sv;
        assert(sv <= sv);
        assert(etl::string_view { "" } <= sv);
        assert(sv.substr(0, 1) <= sv);
        assert("abc"_sv <= sv);
    }

    {
        auto const sv = "test"_sv;
        assert(!(sv > sv));
        assert(etl::string_view { "xxxxxx" } > sv);
        assert(sv > sv.substr(0, 1));
        assert(sv > "abc"_sv);
    }

    {
        auto const sv = "test"_sv;
        assert(sv >= sv);
        assert(etl::string_view { "xxxxxx" } >= sv);
        assert(sv >= sv.substr(0, 1));
        assert(sv >= "abc"_sv);
    }

    {
        auto const sv = "test"_sv;
        assert(sv.size() >= 4);
        assert(sv[0] >= 't');
    }

    {
        assert(("foo"_sv == "foo"_sv));
        assert(("bar"_sv == "bar"_sv));

        assert(!("foo"_sv == etl::static_string<16> { "baz" }));
        assert(("bar"_sv == etl::static_string<16> { "bar" }));

        assert((etl::static_string<16> { "bar" } == "bar"_sv));
        assert(!(etl::static_string<16> { "baz" } == "foo"_sv));

        assert(!("foo"_sv == "test"_sv));
        assert(!("test"_sv == "foo"_sv));
    }
    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
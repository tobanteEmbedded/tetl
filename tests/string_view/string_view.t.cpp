// SPDX-License-Identifier: BSL-1.0

#include <etl/string_view.hpp>

#include <etl/string.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

using etl::string_view;
using namespace etl::literals;

constexpr auto test() -> bool
{
    {
        // P2251R1
        CHECK(etl::is_trivially_copyable_v<etl::string_view>);
    }

    {
        CHECK(string_view{}.data() == nullptr);
        CHECK(string_view{}.size() == 0);
        CHECK(string_view{}.length() == 0);
    }

    {
        auto const sv1 = string_view{};
        auto const sv2 = sv1;

        CHECK(sv2.data() == nullptr);
        CHECK(sv2.size() == 0);
        CHECK(sv2.length() == 0);
    }

    {
        auto const sv1 = "test"_sv;
        auto const sv2 = sv1;

        CHECK(sv2.data() != nullptr);
        CHECK(sv2.size() == 4);
        CHECK(sv2.length() == 4);
    }

    {
        auto const sv = string_view{};
        CHECK(sv.data() == nullptr);
        CHECK(sv.begin() == sv.cbegin());
    }

    {
        auto const sv = "test"_sv;
        CHECK(*sv.begin() == 't');
        CHECK(sv.begin() == sv.cbegin());
    }

    {
        auto const sv = string_view{};
        CHECK(sv.data() == nullptr);
        CHECK(sv.end() == sv.cend());
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.end() == sv.begin() + 4);
        CHECK(sv.end() == sv.cend());
    }

    {
        auto const sv = string_view{};
        CHECK(sv.data() == nullptr);
        CHECK(sv.rend() == sv.crend());
        CHECK(sv.data() == nullptr);
        CHECK(sv.rbegin() == sv.crbegin());
    }

    {
        auto const sv = "abc"_sv;
        CHECK(*sv.rbegin() == 'c');
        CHECK(sv.rbegin() == sv.crbegin());
        CHECK(sv.rend() != sv.rbegin());
        CHECK(sv.rend() == sv.crend());
    }

    {
        auto const sv = "test"_sv;
        auto counter  = string_view::size_type{0};
        for (auto c : sv) {
            etl::ignore_unused(c);
            counter++;
        }

        CHECK(counter == sv.size());
        CHECK(counter == 4);
    }
    {
        auto const sv1 = "test"_sv;
        CHECK(sv1[0] == 't');
        CHECK(sv1[1] == 'e');
        CHECK(sv1[2] == 's');
        CHECK(sv1[3] == 't');

        auto sv2 = string_view{"tobi"};
        CHECK(sv2[0] == 't');
        CHECK(sv2[1] == 'o');
        CHECK(sv2[2] == 'b');
        CHECK(sv2[3] == 'i');
    }

    {
        auto const sv1 = "test"_sv;
        CHECK(sv1.front() == 't');

        auto sv2 = "abc"_sv;
        CHECK(sv2.front() == 'a');
    }
    {
        auto const sv1 = "test"_sv;
        CHECK(sv1.back() == 't');

        auto sv2 = "abc"_sv;
        CHECK(sv2.back() == 'c');
    }
    {
        auto const sv = "test"_sv;
        CHECK(sv.max_size() == string_view::size_type(-1));
    }

    {
        auto const t = string_view{};
        CHECK(t.empty());

        auto const f = "test"_sv;
        CHECK(!f.empty());
    }

    {
        auto sv = string_view{};
        CHECK(sv.empty());
        sv.remove_prefix(0);
        CHECK(sv.empty());
    }

    {
        auto sv = "test"_sv;
        CHECK(sv.size() == 4);
        sv.remove_prefix(1);
        CHECK(sv.size() == 3);
        CHECK(sv[0] == 'e');
    }

    {
        auto sv = string_view{};
        CHECK(sv.empty());
        sv.remove_suffix(0);
        CHECK(sv.empty());
    }

    {
        auto sv = "test"_sv;
        CHECK(sv.size() == 4);

        sv.remove_suffix(1);
        CHECK(sv.size() == 3);
        CHECK(sv[0] == 't');
        CHECK(sv[1] == 'e');
        CHECK(sv[2] == 's');

        sv.remove_suffix(2);
        CHECK(sv.size() == 1);
        CHECK(sv[0] == 't');
    }

    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        CHECK(sv.copy(&buffer[0], 2, 0) == 2);
        CHECK(buffer[0] == 't');
        CHECK(buffer[1] == 'e');
        CHECK(buffer[2] == 0);
        CHECK(buffer[3] == 0);
    }

    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        CHECK(sv.copy(&buffer[0], 2, 1) == 2);
        CHECK(buffer[0] == 'e');
        CHECK(buffer[1] == 's');
        CHECK(buffer[2] == 0);
        CHECK(buffer[3] == 0);
    }

    {
        char buffer[4] = {};
        auto sv        = "test"_sv;
        CHECK(sv.copy(&buffer[0], 2, 3) == 1);
        CHECK(buffer[0] == 't');
        CHECK(buffer[1] == 0);
        CHECK(buffer[2] == 0);
        CHECK(buffer[3] == 0);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.starts_with("t"_sv));
        CHECK(sv.starts_with(string_view{"te"}));
        CHECK(sv.starts_with(string_view{"tes"}));
        CHECK(sv.starts_with("test"_sv));
    }

    {
        auto const sv = "abc"_sv;
        CHECK(sv.starts_with('a'));
    }

    {
        auto const sv = "abc"_sv;
        CHECK(sv.starts_with("a"));
        CHECK(sv.starts_with("ab"));
        CHECK(sv.starts_with("abc"));
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.ends_with("t"_sv));
        CHECK(sv.ends_with("st"_sv));
        CHECK(sv.ends_with("est"_sv));
        CHECK(sv.ends_with("test"_sv));
    }

    {
        auto const sv = "abc"_sv;
        CHECK(sv.ends_with('c'));
        CHECK(!(sv.ends_with('a')));
    }

    {
        auto const sv = "abc"_sv;
        CHECK(sv.ends_with("c"));
        CHECK(sv.ends_with("bc"));
        CHECK(sv.ends_with("abc"));
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find("t"_sv) == 0);
        CHECK(sv.find("est"_sv) == 1);

        CHECK(sv.find("st"_sv, 1) == 2);
        CHECK(sv.find("st"_sv, 2) == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find('t') == 0);
        CHECK(sv.find('e') == 1);

        CHECK(sv.find('s') == 2);
        CHECK(sv.find('s', 2) == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find("t", 0, 1) == 0);
        CHECK(sv.find("est", 0, 3) == 1);

        CHECK(sv.find("x", 0, 1) == string_view::npos);
        CHECK(sv.find("foo", 0, 3) == string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find("t", 0) == 0);
        CHECK(sv.find("est", 0) == 1);

        CHECK(sv.find("x", 0) == string_view::npos);
        CHECK(sv.find("foo", 0) == string_view::npos);

        CHECK(sv.find("xxxxx", 0) == string_view::npos);
        CHECK(sv.find("foobarbaz", 0) == string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.rfind("t"_sv) == 3);
        CHECK(sv.rfind("est"_sv) == 1);

        CHECK(sv.rfind("st"_sv, 12) == 2);
        CHECK(sv.rfind("st"_sv, 12) == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.rfind('t') == 3);
        CHECK(sv.rfind('e') == 1);

        CHECK(sv.rfind('s') == 2);
        CHECK(sv.rfind('s', 2) == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.rfind("t", string_view::npos, 1) == 3);
        CHECK(sv.rfind("est", string_view::npos, 3) == 1);

        CHECK(sv.rfind("x", string_view::npos, 1) == string_view::npos);
        CHECK(sv.rfind("foo", string_view::npos, 3) == string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.rfind("t", string_view::npos) == 3);
        CHECK(sv.rfind("est", string_view::npos) == 1);

        CHECK(sv.rfind("x", 0) == string_view::npos);
        CHECK(sv.rfind("foo", 0) == string_view::npos);

        CHECK(sv.rfind("xxxxx", 0) == string_view::npos);
        CHECK(sv.rfind("foobarbaz", 0) == string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_first_of("t"_sv) == 0);
        CHECK(sv.find_first_of("est"_sv) == 0);

        CHECK(sv.find_first_of("t"_sv, 1) == 3);
        CHECK(sv.find_first_of("st"_sv, 2) == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_first_of('t') == 0);
        CHECK(sv.find_first_of('e') == 1);

        CHECK(sv.find_first_of('t', 1) == 3);
        CHECK(sv.find_first_of('s') == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_first_of("t", 0, 1) == 0);
        CHECK(sv.find_first_of("est", 0, 3) == 0);

        CHECK(sv.find_first_of("x", 0, 1) == string_view::npos);
        CHECK(sv.find_first_of("foo", 0, 3) == string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_first_of("t", 1) == 3);
        CHECK(sv.find_first_of("est", 1) == 1);

        CHECK(sv.find_first_of("x", 0) == string_view::npos);
        CHECK(sv.find_first_of("foo", 0) == string_view::npos);

        CHECK(sv.find_first_of("xxxxx", 0) == string_view::npos);
        CHECK(sv.find_first_of("foobarbaz", 0) == string_view::npos);
    }

    {
        CHECK("BCDEF"_sv.find_first_not_of("ABC") == 2);
        CHECK("BCDEF"_sv.find_first_not_of("ABC", 4) == 4);
        CHECK("BCDEF"_sv.find_first_not_of('B') == 1);
        CHECK("BCDEF"_sv.find_first_not_of('D', 2) == 3);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_last_of("t"_sv) == 3);
        CHECK(sv.find_last_of("est"_sv) == 3);

        CHECK(sv.find_last_of("t"_sv, 1) == 0);
        CHECK(sv.find_last_of("st"_sv, 2) == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_last_of('t') == 3);
        CHECK(sv.find_last_of('e') == 1);
        CHECK(sv.find_last_of('s') == 2);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_last_of("t", 12, 1) == 3);
        CHECK(sv.find_last_of("es", 12, 2) == 2);

        CHECK(sv.find_last_of("x", 0, 1) == etl::string_view::npos);
        CHECK(sv.find_last_of("foo", 0, 3) == etl::string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_last_of("t") == 3);
        CHECK(sv.find_last_of("es") == 2);

        CHECK(sv.find_last_of("x") == etl::string_view::npos);
        CHECK(sv.find_last_of("foo") == etl::string_view::npos);

        CHECK(sv.find_last_of("xxxxx") == etl::string_view::npos);
        CHECK(sv.find_last_of("foobarbaz") == etl::string_view::npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_last_not_of("t"_sv) == 2);
        CHECK(sv.find_last_not_of("est"_sv) == sv.npos);
        CHECK(sv.find_last_not_of(etl::string_view{"s"}, 2) == 1);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_last_not_of('t') == 2);
        CHECK(sv.find_last_not_of('e') == 3);
        CHECK(sv.find_last_not_of('s') == 3);
    }

    {
        auto const npos = etl::string_view::npos;
        auto const sv   = "test"_sv;
        CHECK(sv.find_last_not_of("t", npos, 1) == 2);
        CHECK(sv.find_last_not_of("es", npos, 2) == 3);
        CHECK(sv.find_last_not_of("est", npos, 4) == npos);
        CHECK(sv.find_last_not_of("tes", npos, 4) == npos);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.find_last_not_of("t") == 2);
        CHECK(sv.find_last_not_of("es") == 3);

        CHECK(sv.find_last_not_of("tes") == etl::string_view::npos);
        CHECK(sv.find_last_not_of("est") == etl::string_view::npos);
    }

    {
        auto const sv = "test"_sv;

        auto const sub1 = sv.substr(0, 1);
        CHECK(sub1.size() == 1);
        CHECK(sub1[0] == 't');

        auto const sub2 = sv.substr(0, 2);
        CHECK(sub2.size() == 2);
        CHECK(sub2[0] == 't');
        CHECK(sub2[1] == 'e');

        auto const sub3 = sv.substr(2, 2);
        CHECK(sub3.size() == 2);
        CHECK(sub3[0] == 's');
        CHECK(sub3[1] == 't');
    }

    {
        auto lhs = etl::string_view();
        auto rhs = etl::string_view();

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    {
        auto const lhs = "test"_sv;
        auto const rhs = "test"_sv;

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

        CHECK("te"_sv.compare(0, 2, "test"_sv, 0, 2) == 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 3) == 0);
        CHECK("abcabc"_sv.compare(3, 1, "abc"_sv, 0, 3) < 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 1) > 0);

        CHECK("abcabc"_sv.compare(3, 3, "abc", 3) == 0);
        CHECK("abcabc"_sv.compare(3, 1, "abc", 0, 3) < 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc", 0, 1) > 0);
    }

    {
        auto const lhs = "test"_sv;
        auto const rhs = "te"_sv;

        CHECK(lhs.compare(rhs) > 0);
        CHECK(rhs.compare("test"_sv) < 0);
    }

    {
        auto const sv  = "test"_sv;
        auto const str = etl::static_string<16>{"test"};
        CHECK(!(sv < sv));
        CHECK(etl::string_view{""} < sv);
        CHECK(sv.substr(0, 1) < sv);
        CHECK("abc"_sv < sv);
        CHECK(!(sv < str));
        CHECK(!(str < sv));
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv <= sv);
        CHECK(etl::string_view{""} <= sv);
        CHECK(sv.substr(0, 1) <= sv);
        CHECK("abc"_sv <= sv);
    }

    {
        auto const sv = "test"_sv;
        CHECK(!(sv > sv));
        CHECK(etl::string_view{"xxxxxx"} > sv);
        CHECK(sv > sv.substr(0, 1));
        CHECK(sv > "abc"_sv);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv >= sv);
        CHECK(etl::string_view{"xxxxxx"} >= sv);
        CHECK(sv >= sv.substr(0, 1));
        CHECK(sv >= "abc"_sv);
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.size() >= 4);
        CHECK(sv[0] >= 't');
    }

    {
        CHECK("foo"_sv == "foo"_sv);
        CHECK("bar"_sv == "bar"_sv);

        CHECK(!("foo"_sv == etl::static_string<16>{"baz"}));
        CHECK("bar"_sv == etl::static_string<16>{"bar"});

        CHECK(etl::static_string<16>{"bar"} == "bar"_sv);
        CHECK(!(etl::static_string<16>{"baz"} == "foo"_sv));

        CHECK(!("foo"_sv == "test"_sv));
        CHECK(!("test"_sv == "foo"_sv));
    }
    return true;
}

auto main() -> int
{
    CHECK(test());
    static_assert(test());
    return 0;
}

// SPDX-License-Identifier: BSL-1.0

#include <etl/string_view.hpp>

#include <etl/string.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using namespace etl::literals;

    {
        // P2251R1
        CHECK(etl::is_trivially_copyable_v<etl::string_view>);
    }

    {
        CHECK(etl::string_view{}.data() == nullptr);
        CHECK(etl::string_view{}.size() == 0);
        CHECK(etl::string_view{}.length() == 0);
    }

    {
        auto const sv1 = etl::string_view{};
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
        auto const sv = etl::string_view{};
        CHECK(sv.data() == nullptr);
        CHECK(sv.begin() == sv.cbegin());
    }

    {
        auto const sv = "test"_sv;
        CHECK(*sv.begin() == 't');
        CHECK(sv.begin() == sv.cbegin());
    }

    {
        auto const sv = etl::string_view{};
        CHECK(sv.data() == nullptr);
        CHECK(sv.end() == sv.cend());
    }

    {
        auto const sv = "test"_sv;
        CHECK(sv.end() == sv.begin() + 4);
        CHECK(sv.end() == sv.cend());
    }

    {
        auto const sv = etl::string_view{};
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
        auto counter  = etl::string_view::size_type{0};
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

        auto sv2 = etl::string_view{"tobi"};
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
        CHECK(sv.max_size() == etl::string_view::size_type(-1));
    }

    {
        auto const t = etl::string_view{};
        CHECK(t.empty());

        auto const f = "test"_sv;
        CHECK_FALSE(f.empty());
    }

    {
        auto sv = etl::string_view{};
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
        auto sv = etl::string_view{};
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
        auto const str = etl::inplace_string<16>{"test"};
        CHECK_FALSE(sv < sv);
        CHECK(etl::string_view{""} < sv);
        CHECK(sv.substr(0, 1) < sv);
        CHECK("abc"_sv < sv);
        CHECK_FALSE(sv < str);
        CHECK_FALSE(str < sv);
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
        CHECK_FALSE(sv > sv);
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

        CHECK_FALSE("foo"_sv == etl::inplace_string<16>{"baz"});
        CHECK("bar"_sv == etl::inplace_string<16>{"bar"});

        CHECK(etl::inplace_string<16>{"bar"} == "bar"_sv);
        CHECK_FALSE(etl::inplace_string<16>{"baz"} == "foo"_sv);

        CHECK_FALSE("foo"_sv == "test"_sv);
        CHECK_FALSE("test"_sv == "foo"_sv);
    }
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}

// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/compare.hpp>
    #include <etl/string.hpp>
#endif

namespace {

template <typename Char>
[[nodiscard]] constexpr auto test() -> bool
{
    using traits = etl::char_traits<Char>;

    CHECK_SAME_TYPE(typename traits::char_type, Char);
    CHECK_SAME_TYPE(typename traits::comparison_category, etl::strong_ordering);

    // assign
    {
        auto dest = Char();
        for (auto ch : etl::array{Char('A'), Char('b'), Char('0')}) {
            traits::assign(dest, ch);
            CHECK(dest == ch);
        }
    }

    // eq
    CHECK(traits::eq(Char('A'), Char('A')));
    CHECK_FALSE(traits::eq(Char('A'), Char('B')));
    CHECK_FALSE(traits::eq(Char('A'), Char('a')));
    CHECK_FALSE(traits::eq(Char('A'), Char('0')));

    // lt
    CHECK(traits::lt(Char('A'), Char('B')));
    CHECK(traits::lt(Char('A'), Char('a')));
    CHECK_FALSE(traits::lt(Char('A'), Char('A')));
    CHECK_FALSE(traits::lt(Char('A'), Char('0')));

    // compare
    {
        auto lhs = etl::array{Char('A'), Char('B'), Char('C'), Char('D'), Char(0)};
        auto rhs = etl::array{Char('A'), Char('B'), Char('C'), Char('E'), Char(0)};
        CHECK(traits::compare(lhs.data(), lhs.data(), lhs.size()) == 0);
        CHECK(traits::compare(rhs.data(), rhs.data(), rhs.size()) == 0);
        CHECK(traits::compare(lhs.data(), rhs.data(), lhs.size()) == -1);
        CHECK(traits::compare(rhs.data(), lhs.data(), lhs.size()) == +1);
    }

    // copy
    {
        auto const src = etl::array<Char, 4>{Char('A'), Char('B'), Char('C'), Char('D')};

        {
            auto dest = etl::array<Char, 4>{};
            traits::copy(dest.data(), src.data(), 0);
            CHECK(dest == etl::array<Char, 4>{});
        }

        {
            auto dest = etl::array<Char, 4>{};
            traits::copy(dest.data(), src.data(), src.size());
            CHECK(dest == src);
        }
    }

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test<char>());
    CHECK(test<wchar_t>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}

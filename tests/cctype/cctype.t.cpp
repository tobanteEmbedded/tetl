// SPDX-License-Identifier: BSL-1.0

#include <etl/cctype.hpp>

#include "testing/testing.hpp"

static constexpr auto test_isalnum() -> bool
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK(etl::isalnum(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK(etl::isalnum(ch));
    }
    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK(etl::isalnum(ch));
    }

    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::isalnum(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::isalnum(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::isalnum(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::isalnum(ch));
    }

    return true;
}

static constexpr auto test_isalpha() -> bool
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK(etl::isalpha(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK(etl::isalpha(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK_FALSE(etl::isalpha(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::isalpha(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::isalpha(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::isalpha(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::isalpha(ch));
    }
    return true;
}

static constexpr auto test_islower() -> bool
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK(etl::islower(ch));
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK_FALSE(etl::islower(ch));
    }
    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK_FALSE(etl::islower(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::islower(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::islower(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::islower(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::islower(ch));
    }
    return true;
}

static constexpr auto test_isupper() -> bool
{
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK(etl::isupper(ch));
    }

    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK_FALSE(etl::isupper(ch));
    }
    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK_FALSE(etl::isupper(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::isupper(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::isupper(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::isupper(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::isupper(ch));
    }
    return true;
}

static constexpr auto test_isdigit() -> bool
{
    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK(etl::isdigit(ch));
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK_FALSE(etl::isdigit(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK_FALSE(etl::isdigit(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::isdigit(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::isdigit(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::isdigit(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::isdigit(ch));
    }
    return true;
}

static constexpr auto test_isxdigit() -> bool
{
    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK(etl::isxdigit(ch));
    }
    for (auto ch = 'A'; ch <= 'F'; ++ch) {
        CHECK(etl::isxdigit(ch));
    }
    for (auto ch = 'a'; ch <= 'f'; ++ch) {
        CHECK(etl::isxdigit(ch));
    }

    for (auto ch = 'G'; ch <= 'Z'; ++ch) {
        CHECK_FALSE(etl::isxdigit(ch));
    }
    for (auto ch = 'g'; ch <= 'z'; ++ch) {
        CHECK_FALSE(etl::isxdigit(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::isxdigit(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::isxdigit(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::isxdigit(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::isxdigit(ch));
    }
    return true;
}

static constexpr auto test_isspace() -> bool
{
    CHECK(etl::isspace(' '));
    CHECK(etl::isspace('\f'));
    CHECK(etl::isspace('\n'));
    CHECK(etl::isspace('\r'));
    CHECK(etl::isspace('\t'));
    CHECK(etl::isspace('\v'));

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK_FALSE(etl::isspace(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK_FALSE(etl::isspace(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK_FALSE(etl::isspace(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::isspace(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::isspace(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::isspace(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::isspace(ch));
    }
    return true;
}

static constexpr auto test_isblank() -> bool
{
    CHECK(etl::isblank(' '));
    CHECK(etl::isblank('\t'));

    CHECK_FALSE(etl::isblank('\f'));
    CHECK_FALSE(etl::isblank('\n'));
    CHECK_FALSE(etl::isblank('\r'));
    CHECK_FALSE(etl::isblank('\v'));

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK_FALSE(etl::isblank(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK_FALSE(etl::isblank(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK_FALSE(etl::isblank(ch));
    }

    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::isblank(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::isblank(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::isblank(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::isblank(ch));
    }
    return true;
}

static constexpr auto test_ispunct() -> bool
{
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK(etl::ispunct(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK(etl::ispunct(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK(etl::ispunct(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK(etl::ispunct(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK_FALSE(etl::ispunct(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK_FALSE(etl::ispunct(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK_FALSE(etl::ispunct(ch));
    }
    return true;
}

static constexpr auto test_isgraph() -> bool
{
    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK(etl::isgraph(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK(etl::isgraph(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK(etl::isgraph(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK(etl::isgraph(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK(etl::isgraph(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK(etl::isgraph(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK(etl::isgraph(ch));
    }

    CHECK_FALSE(etl::isgraph(' '));
    CHECK_FALSE(etl::isgraph('\n'));
    CHECK_FALSE(etl::isgraph('\f'));
    CHECK_FALSE(etl::isgraph('\t'));
    CHECK_FALSE(etl::isgraph('\v'));
    return true;
}

static constexpr auto test_isprint() -> bool
{
    CHECK(etl::isprint(' '));

    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK(etl::isprint(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK(etl::isprint(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK(etl::isprint(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK(etl::isprint(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK(etl::isprint(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK(etl::isprint(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK(etl::isprint(ch));
    }

    CHECK_FALSE(etl::isprint('\n'));
    CHECK_FALSE(etl::isprint('\f'));
    CHECK_FALSE(etl::isprint('\t'));
    CHECK_FALSE(etl::isprint('\v'));

    return true;
}

static constexpr auto test_iscntrl() -> bool
{
    CHECK(etl::iscntrl(0x7F));
    for (auto ch = 0x00; ch <= 0x1F; ++ch) {
        CHECK(etl::iscntrl(ch));
    }

    for (auto ch = '!'; ch <= '/'; ++ch) {
        CHECK_FALSE(etl::iscntrl(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        CHECK_FALSE(etl::iscntrl(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        CHECK_FALSE(etl::iscntrl(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        CHECK_FALSE(etl::iscntrl(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK_FALSE(etl::iscntrl(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK_FALSE(etl::iscntrl(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK_FALSE(etl::iscntrl(ch));
    }

    return true;
}

static constexpr auto test_tolower() -> bool
{
    CHECK(static_cast<char>(etl::tolower('a')) == 'a');
    CHECK(static_cast<char>(etl::tolower('A')) == 'a');

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK(static_cast<char>(etl::tolower(ch)) == ch);
    }

    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK(static_cast<char>(etl::tolower(ch)) == ch);
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK(static_cast<char>(etl::tolower(ch)) == ch + 32);
    }

    return true;
}

static constexpr auto test_toupper() -> bool
{
    CHECK(static_cast<char>(etl::toupper('a')) == 'A');
    CHECK(static_cast<char>(etl::toupper('A')) == 'A');

    for (auto ch = '0'; ch <= '9'; ++ch) {
        CHECK(static_cast<char>(etl::toupper(ch)) == ch);
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        CHECK(static_cast<char>(etl::toupper(ch)) == ch);
    }

    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        CHECK(static_cast<char>(etl::toupper(ch)) == ch - 32);
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_isalnum());
    STATIC_CHECK(test_isalpha());
    STATIC_CHECK(test_islower());
    STATIC_CHECK(test_isupper());
    STATIC_CHECK(test_isdigit());
    STATIC_CHECK(test_isxdigit());
    STATIC_CHECK(test_isspace());
    STATIC_CHECK(test_isblank());
    STATIC_CHECK(test_ispunct());
    STATIC_CHECK(test_isgraph());
    STATIC_CHECK(test_isprint());
    STATIC_CHECK(test_iscntrl());
    STATIC_CHECK(test_tolower());
    STATIC_CHECK(test_toupper());
    return 0;
}

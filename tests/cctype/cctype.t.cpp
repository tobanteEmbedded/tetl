// SPDX-License-Identifier: BSL-1.0

#include <etl/cctype.hpp>

#include "testing/testing.hpp"

constexpr auto test_isalnum() -> bool
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(etl::isalnum(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(etl::isalnum(ch));
    }
    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(etl::isalnum(ch));
    }

    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::isalnum(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::isalnum(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::isalnum(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::isalnum(ch));
    }

    return true;
}

constexpr auto test_isalpha() -> bool
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(etl::isalpha(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(etl::isalpha(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(!etl::isalpha(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::isalpha(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::isalpha(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::isalpha(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::isalpha(ch));
    }
    return true;
}

constexpr auto test_islower() -> bool
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(etl::islower(ch));
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(!etl::islower(ch));
    }
    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(!etl::islower(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::islower(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::islower(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::islower(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::islower(ch));
    }
    return true;
}

constexpr auto test_isupper() -> bool
{
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(etl::isupper(ch));
    }

    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(!etl::isupper(ch));
    }
    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(!etl::isupper(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::isupper(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::isupper(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::isupper(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::isupper(ch));
    }
    return true;
}

constexpr auto test_isdigit() -> bool
{
    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(etl::isdigit(ch));
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(!etl::isdigit(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(!etl::isdigit(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::isdigit(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::isdigit(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::isdigit(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::isdigit(ch));
    }
    return true;
}

constexpr auto test_isxdigit() -> bool
{
    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(etl::isxdigit(ch));
    }
    for (auto ch = 'A'; ch <= 'F'; ++ch) {
        assert(etl::isxdigit(ch));
    }
    for (auto ch = 'a'; ch <= 'f'; ++ch) {
        assert(etl::isxdigit(ch));
    }

    for (auto ch = 'G'; ch <= 'Z'; ++ch) {
        assert(!etl::isxdigit(ch));
    }
    for (auto ch = 'g'; ch <= 'z'; ++ch) {
        assert(!etl::isxdigit(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::isxdigit(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::isxdigit(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::isxdigit(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::isxdigit(ch));
    }
    return true;
}

constexpr auto test_isspace() -> bool
{
    assert(etl::isspace(' '));
    assert(etl::isspace('\f'));
    assert(etl::isspace('\n'));
    assert(etl::isspace('\r'));
    assert(etl::isspace('\t'));
    assert(etl::isspace('\v'));

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(!etl::isspace(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(!etl::isspace(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(!etl::isspace(ch));
    }
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::isspace(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::isspace(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::isspace(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::isspace(ch));
    }
    return true;
}

constexpr auto test_isblank() -> bool
{
    assert(etl::isblank(' '));
    assert(etl::isblank('\t'));

    assert(!etl::isblank('\f'));
    assert(!etl::isblank('\n'));
    assert(!etl::isblank('\r'));
    assert(!etl::isblank('\v'));

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(!etl::isblank(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(!etl::isblank(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(!etl::isblank(ch));
    }

    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::isblank(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::isblank(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::isblank(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::isblank(ch));
    }
    return true;
}

constexpr auto test_ispunct() -> bool
{
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(etl::ispunct(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(etl::ispunct(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(etl::ispunct(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(etl::ispunct(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(!etl::ispunct(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(!etl::ispunct(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(!etl::ispunct(ch));
    }
    return true;
}

constexpr auto test_isgraph() -> bool
{
    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(etl::isgraph(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(etl::isgraph(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(etl::isgraph(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(etl::isgraph(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(etl::isgraph(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(etl::isgraph(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(etl::isgraph(ch));
    }

    assert(!etl::isgraph(' '));
    assert(!etl::isgraph('\n'));
    assert(!etl::isgraph('\f'));
    assert(!etl::isgraph('\t'));
    assert(!etl::isgraph('\v'));
    return true;
}

constexpr auto test_isprint() -> bool
{
    assert(etl::isprint(' '));

    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(etl::isprint(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(etl::isprint(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(etl::isprint(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(etl::isprint(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(etl::isprint(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(etl::isprint(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(etl::isprint(ch));
    }

    assert(!etl::isprint('\n'));
    assert(!etl::isprint('\f'));
    assert(!etl::isprint('\t'));
    assert(!etl::isprint('\v'));

    return true;
}

constexpr auto test_iscntrl() -> bool
{
    assert(etl::iscntrl(0x7F));
    for (auto ch = 0x00; ch <= 0x1F; ++ch) {
        assert(etl::iscntrl(ch));
    }

    for (auto ch = '!'; ch <= '/'; ++ch) {
        assert(!etl::iscntrl(ch));
    }
    for (auto ch = ':'; ch <= '@'; ++ch) {
        assert(!etl::iscntrl(ch));
    }
    for (auto ch = '['; ch <= '`'; ++ch) {
        assert(!etl::iscntrl(ch));
    }
    for (auto ch = '{'; ch <= '~'; ++ch) {
        assert(!etl::iscntrl(ch));
    }

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(!etl::iscntrl(ch));
    }
    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(!etl::iscntrl(ch));
    }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(!etl::iscntrl(ch));
    }

    return true;
}

constexpr auto test_tolower() -> bool
{
    assert(static_cast<char>(etl::tolower('a')) == 'a');
    assert(static_cast<char>(etl::tolower('A')) == 'a');

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(static_cast<char>(etl::tolower(ch)) == ch);
    }

    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(static_cast<char>(etl::tolower(ch)) == ch);
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(static_cast<char>(etl::tolower(ch)) == ch + 32);
    }

    return true;
}

constexpr auto test_toupper() -> bool
{
    assert(static_cast<char>(etl::toupper('a')) == 'A');
    assert(static_cast<char>(etl::toupper('A')) == 'A');

    for (auto ch = '0'; ch <= '9'; ++ch) {
        assert(static_cast<char>(etl::toupper(ch)) == ch);
    }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) {
        assert(static_cast<char>(etl::toupper(ch)) == ch);
    }

    for (auto ch = 'a'; ch <= 'z'; ++ch) {
        assert(static_cast<char>(etl::toupper(ch)) == ch - 32);
    }

    return true;
}

auto main() -> int
{
    assert(test_isalnum());
    assert(test_isalpha());
    assert(test_islower());
    assert(test_isupper());
    assert(test_isdigit());
    assert(test_isxdigit());
    assert(test_isspace());
    assert(test_isblank());
    assert(test_ispunct());
    assert(test_isgraph());
    assert(test_isprint());
    assert(test_iscntrl());
    assert(test_tolower());
    assert(test_toupper());

    static_assert(test_isalnum());
    static_assert(test_isalpha());
    static_assert(test_islower());
    static_assert(test_isupper());
    static_assert(test_isdigit());
    static_assert(test_isxdigit());
    static_assert(test_isspace());
    static_assert(test_isblank());
    static_assert(test_ispunct());
    static_assert(test_isgraph());
    static_assert(test_isprint());
    static_assert(test_iscntrl());
    static_assert(test_tolower());
    static_assert(test_toupper());
    return 0;
}

/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cctype.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("cctype: isalnum", "[cctype]")
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK(etl::isalnum(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK(etl::isalnum(ch)); }
    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK(etl::isalnum(ch)); }

    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::isalnum(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::isalnum(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::isalnum(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::isalnum(ch)); }
}

TEST_CASE("cctype: isalpha", "[cctype]")
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK(etl::isalpha(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK(etl::isalpha(ch)); }

    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK_FALSE(etl::isalpha(ch)); }
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::isalpha(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::isalpha(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::isalpha(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::isalpha(ch)); }
}

TEST_CASE("cctype: islower", "[cctype]")
{
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK(etl::islower(ch)); }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK_FALSE(etl::islower(ch)); }
    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK_FALSE(etl::islower(ch)); }
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::islower(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::islower(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::islower(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::islower(ch)); }
}

TEST_CASE("cctype: isupper", "[cctype]")
{
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK(etl::isupper(ch)); }

    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK_FALSE(etl::isupper(ch)); }
    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK_FALSE(etl::isupper(ch)); }
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::isupper(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::isupper(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::isupper(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::isupper(ch)); }
}

TEST_CASE("cctype: isdigit", "[cctype]")
{
    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK(etl::isdigit(ch)); }

    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK_FALSE(etl::isdigit(ch)); }
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK_FALSE(etl::isdigit(ch)); }
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::isdigit(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::isdigit(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::isdigit(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::isdigit(ch)); }
}

TEST_CASE("cctype: isxdigit", "[cctype]")
{
    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK(etl::isxdigit(ch)); }
    for (auto ch = 'A'; ch <= 'F'; ++ch) { CHECK(etl::isxdigit(ch)); }
    for (auto ch = 'a'; ch <= 'f'; ++ch) { CHECK(etl::isxdigit(ch)); }

    for (auto ch = 'G'; ch <= 'Z'; ++ch) { CHECK_FALSE(etl::isxdigit(ch)); }
    for (auto ch = 'g'; ch <= 'z'; ++ch) { CHECK_FALSE(etl::isxdigit(ch)); }
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::isxdigit(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::isxdigit(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::isxdigit(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::isxdigit(ch)); }
}

TEST_CASE("cctype: isspace", "[cctype]")
{
    CHECK(etl::isspace(' '));
    CHECK(etl::isspace('\f'));
    CHECK(etl::isspace('\n'));
    CHECK(etl::isspace('\r'));
    CHECK(etl::isspace('\t'));
    CHECK(etl::isspace('\v'));

    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK_FALSE(etl::isspace(ch)); }
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK_FALSE(etl::isspace(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK_FALSE(etl::isspace(ch)); }
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::isspace(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::isspace(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::isspace(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::isspace(ch)); }
}

TEST_CASE("cctype: isblank", "[cctype]")
{
    CHECK(etl::isblank(' '));
    CHECK(etl::isblank('\t'));

    CHECK_FALSE(etl::isblank('\f'));
    CHECK_FALSE(etl::isblank('\n'));
    CHECK_FALSE(etl::isblank('\r'));
    CHECK_FALSE(etl::isblank('\v'));

    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK_FALSE(etl::isblank(ch)); }
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK_FALSE(etl::isblank(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK_FALSE(etl::isblank(ch)); }

    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::isblank(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::isblank(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::isblank(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::isblank(ch)); }
}

TEST_CASE("cctype: ispunct", "[cctype]")
{
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK(etl::ispunct(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK(etl::ispunct(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK(etl::ispunct(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK(etl::ispunct(ch)); }

    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK_FALSE(etl::ispunct(ch)); }
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK_FALSE(etl::ispunct(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK_FALSE(etl::ispunct(ch)); }
}

TEST_CASE("cctype: isgraph", "[cctype]")
{
    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK(etl::isgraph(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK(etl::isgraph(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK(etl::isgraph(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK(etl::isgraph(ch)); }

    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK(etl::isgraph(ch)); }
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK(etl::isgraph(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK(etl::isgraph(ch)); }

    CHECK_FALSE(etl::isgraph(' '));
    CHECK_FALSE(etl::isgraph('\n'));
    CHECK_FALSE(etl::isgraph('\f'));
    CHECK_FALSE(etl::isgraph('\t'));
    CHECK_FALSE(etl::isgraph('\v'));
}

TEST_CASE("cctype: isprint", "[cctype]")
{
    CHECK(etl::isprint(' '));

    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK(etl::isprint(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK(etl::isprint(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK(etl::isprint(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK(etl::isprint(ch)); }

    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK(etl::isprint(ch)); }
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK(etl::isprint(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK(etl::isprint(ch)); }

    CHECK_FALSE(etl::isprint('\n'));
    CHECK_FALSE(etl::isprint('\f'));
    CHECK_FALSE(etl::isprint('\t'));
    CHECK_FALSE(etl::isprint('\v'));
}

TEST_CASE("cctype: iscntrl", "[cctype]")
{
    CHECK(etl::iscntrl(0x7F));
    for (auto ch = 0x00; ch <= 0x1F; ++ch) { CHECK(etl::iscntrl(ch)); }

    for (auto ch = '!'; ch <= '/'; ++ch) { CHECK_FALSE(etl::iscntrl(ch)); }
    for (auto ch = ':'; ch <= '@'; ++ch) { CHECK_FALSE(etl::iscntrl(ch)); }
    for (auto ch = '['; ch <= '`'; ++ch) { CHECK_FALSE(etl::iscntrl(ch)); }
    for (auto ch = '{'; ch <= '~'; ++ch) { CHECK_FALSE(etl::iscntrl(ch)); }

    for (auto ch = '0'; ch <= '9'; ++ch) { CHECK_FALSE(etl::iscntrl(ch)); }
    for (auto ch = 'a'; ch <= 'z'; ++ch) { CHECK_FALSE(etl::iscntrl(ch)); }
    for (auto ch = 'A'; ch <= 'Z'; ++ch) { CHECK_FALSE(etl::iscntrl(ch)); }
}

TEST_CASE("cctype: tolower", "[cctype]")
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
}

TEST_CASE("cctype: toupper", "[cctype]")
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
}
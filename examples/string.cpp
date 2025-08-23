// SPDX-License-Identifier: BSL-1.0

#include <etl/cassert.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/cctype.hpp>
    #include <etl/string.hpp>
#endif

#include <stdio.h>
#include <stdlib.h>

auto main() -> int
{
    // Unlike a std::string you will have to decide which maximum capacity you
    // need. Apart from that it behaves almost the same as the standard version.
    etl::inplace_string<32> str{};
    assert(str.empty());
    static_assert(str.capacity() == 32);

    // You can append/push_back characters, c-strings, string_view and other
    // strings of same or different capacity.
    str.append("Hello", 2);
    assert(str.size() == 2);
    assert(str == "He");

    str.append(2, 'l');
    assert(str.size() == 4);
    assert(str == "Hell");

    str.push_back('o');
    assert(!str.empty());
    assert(str.size() == 5);
    assert(str == "Hello");

    auto other = etl::string_view{" World"};
    str.append(other, 0);
    assert(!str.empty());
    assert(str.size() == 11);
    assert(str == "Hello World");

    // You can make copies.
    auto const copy = str;

    // You can compare strings
    assert(copy == str);

    // You can apply algorithms.
    auto toUpper = [](auto ch) { return static_cast<char>(etl::toupper(ch)); };
    etl::transform(begin(str), end(str), begin(str), toUpper);
    assert(str == "HELLO WORLD");
    assert(copy != str);

    // You can insert at any position
    str.insert(0, 2, ' ');
    assert(str == "  HELLO WORLD");
    str.insert(7, " foo");
    assert(str == "  HELLO foo WORLD");

    // You can check if a inplace_string starts or ends with a substring
    assert(str.starts_with("  "));
    assert(str.ends_with("WORLD"));

    // You can convert a inplace_string into a string_view
    etl::string_view view = str;
    assert(view.size() == str.size());

    // TODO: find & friends

    // to_string
    ::printf("to_string<8>(1): '%s'\n", etl::to_string<8>(1).c_str());
    ::printf("to_string<8>(16384): '%s'\n", etl::to_string<8>(16384).c_str());

    return 0;
}

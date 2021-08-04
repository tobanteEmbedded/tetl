// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#undef NDEBUG

#include "etl/string.hpp" // for static_string

#include "etl/cassert.hpp" // for TETL_ASSERT
#include "etl/cctype.hpp"  // for toupper

#include <stdio.h>  // for printf
#include <stdlib.h> // for EXIT_SUCCESS

auto main() -> int
{
    // Unlike a std::string you will have to decide which maximum capacity you
    // need. Apart from that it behaves almost the same as the standard version.
    etl::static_string<32> str {};
    TETL_ASSERT(str.empty());
    static_assert(str.capacity() == 32);

    // You can append/push_back characters, c-strings, string_view and other
    // strings of same or different capacity.
    str.append("Hello", 2);
    TETL_ASSERT(str.size() == 2);
    TETL_ASSERT(str == "He");

    str.append(2, 'l');
    TETL_ASSERT(str.size() == 4);
    TETL_ASSERT(str == "Hell");

    str.push_back('o');
    TETL_ASSERT(!str.empty());
    TETL_ASSERT(str.size() == 5);
    TETL_ASSERT(str == "Hello");

    auto other = etl::string_view { " World" };
    str.append(other, 0);
    TETL_ASSERT(!str.empty());
    TETL_ASSERT(str.size() == 11);
    TETL_ASSERT(str == "Hello World");

    // You can make copies.
    auto const copy = str;

    // You can compare strings
    TETL_ASSERT(copy == str);

    // You can apply algorithms.
    etl::transform(begin(str), end(str), begin(str), etl::toupper);
    TETL_ASSERT(str == "HELLO WORLD");
    TETL_ASSERT(copy != str);

    // You can insert at any position
    str.insert(0, 2, ' ');
    TETL_ASSERT(str == "  HELLO WORLD");
    str.insert(7, " foo");
    TETL_ASSERT(str == "  HELLO foo WORLD");

    // You can check if a static_string starts or ends with a substring
    TETL_ASSERT(str.starts_with("  "));
    TETL_ASSERT(str.ends_with("WORLD"));

    // You can convert a static_string into a string_view
    etl::string_view view = str;
    TETL_ASSERT(view.size() == str.size());

    // TODO: find & friends

    return EXIT_SUCCESS;
}

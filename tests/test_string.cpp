/*
Copyright (c) 2019, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

// MICROCATCH
#include "micro_catch/micro_catch.hpp"

// TAETL
#include "taetl/algorithm.hpp"
#include "taetl/string.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::String<char, 16> t_string{};

    // INIT
    microcatch::EQUAL(t_string.empty(), true);
    microcatch::EQUAL(t_string.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_string.size(), taetl::size_t(0));
    microcatch::EQUAL(t_string.length(), taetl::size_t(0));

    taetl::for_each(t_string.begin(), t_string.end(), [](auto& c) {
        microcatch::ignoreUnused(c);
        microcatch::EQUAL(c, 0);
    });

    taetl::for_each(t_string.cbegin(), t_string.cend(), [](const auto& c) {
        microcatch::ignoreUnused(c);
        microcatch::EQUAL(c, 0);
    });

    for (const auto& c : t_string)
    {
        microcatch::ignoreUnused(c);
        microcatch::EQUAL(c, 0);
    }

    // APPEND 4 CHARACTERS
    const char* cptr = "C-string";
    t_string.append(cptr, 4);

    microcatch::EQUAL(t_string.empty(), false);
    microcatch::EQUAL(t_string.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_string.size(), taetl::size_t(4));
    microcatch::EQUAL(t_string.length(), taetl::size_t(4));
    microcatch::EQUAL(t_string[0], 'C');
    microcatch::EQUAL(t_string[1], '-');
    microcatch::EQUAL(t_string[2], 's');
    microcatch::EQUAL(t_string[3], 't');
    microcatch::EQUAL(t_string[4], 0);
    microcatch::EQUAL(t_string.at(4), 0);

    // APPEND 5X SAME CHARACTER
    t_string.append(5, 'a');
    const char first_char = t_string[0];

    microcatch::EQUAL(t_string.empty(), false);
    microcatch::EQUAL(t_string.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_string.size(), taetl::size_t(9));
    microcatch::EQUAL(t_string.length(), taetl::size_t(9));
    microcatch::EQUAL(first_char, 'C');
    microcatch::EQUAL(t_string[0], 'C');
    microcatch::EQUAL(t_string[1], '-');
    microcatch::EQUAL(t_string[2], 's');
    microcatch::EQUAL(t_string[3], 't');
    microcatch::EQUAL(t_string[4], 'a');
    microcatch::EQUAL(t_string[5], 'a');
    microcatch::EQUAL(t_string[6], 'a');
    microcatch::EQUAL(t_string[7], 'a');
    microcatch::EQUAL(t_string[8], 'a');
    microcatch::EQUAL(t_string[9], 0);
    microcatch::EQUAL(t_string.at(9), 0);

    // APPLY ALGORITHM
    taetl::for_each(t_string.begin(), t_string.end(), [](auto& c) { c += 1; });
    microcatch::EQUAL(t_string[4], 'b');
    microcatch::EQUAL(t_string[5], 'b');
    microcatch::EQUAL(t_string[6], 'b');
    microcatch::EQUAL(t_string[7], 'b');
    microcatch::EQUAL(t_string[8], 'b');

    // CLEAR
    t_string.clear();
    microcatch::EQUAL(t_string.capacity(), taetl::size_t(16));
    microcatch::EQUAL(t_string.empty(), true);
    microcatch::EQUAL(t_string.size(), taetl::size_t(0));

    for (const auto& c : t_string)
    {
        microcatch::ignoreUnused(c);
        microcatch::EQUAL(c, 0);
    }

    return 0;
}
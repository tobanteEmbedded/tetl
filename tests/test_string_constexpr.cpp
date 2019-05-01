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

// TAETL
#include "taetl/string.hpp"

int main()
{
    constexpr taetl::String<char, 16> t_string{};

    static_assert(t_string.empty() == true, "String empty");
    static_assert(t_string.capacity() == 16, "String capacity");
    static_assert(t_string.size() == 0, "String size");
    static_assert(t_string.length() == 0, "String length");

    constexpr auto t_string_2 = []() {
        taetl::String<char, 16> str{};
        // APPEND 4 CHARACTERS
        const char* cptr = "C-string";
        str.append(cptr, 4);
        return str;
    }();

    static_assert(t_string_2.empty() == false, "String empty");
    static_assert(t_string_2.capacity() == 16, "String capacity");
    static_assert(t_string_2.size() == 4, "String size");
    static_assert(t_string_2.length() == 4, "String length");
    static_assert(t_string_2[0] == 'C', "String element");
    static_assert(t_string_2[1] == '-', "String element");
    static_assert(t_string_2[2] == 's', "String element");
    static_assert(t_string_2[3] == 't', "String element");
    static_assert(t_string_2[4] == 0, "String element");
    static_assert(t_string_2.at(4) == 0, "String element");

    return 0;
}
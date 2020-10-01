/*
Copyright (c) 2019-2020, Tobias Hienzsch
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

#ifndef TAETL_CSTDLIB_HPP
#define TAETL_CSTDLIB_HPP

#include "cassert.hpp"
#include "cstring.hpp"
#include "definitions.hpp"

namespace etl
{
/**
 * @brief Converts an integer value to a null-terminated string using the specified base
 * and stores the result in the array given by str parameter.
 *
 * @details If base is 10 and value is negative, the resulting string is preceded with a
 * minus sign (-). With any other base, value is always considered unsigned.
 *
 * @todo Only base 10 is currently supported.
 */
constexpr auto itoa(int val, char* const buffer, int base) -> char*
{
    switch (base)
    {
    case 10:
    {
        auto digits10 = [](auto x) {
            auto result = 1;
            while (true)
            {
                if (x < 10) { return result; }
                if (x < 100) { return result + 1; }
                if (x < 1'000) { return result + 2; }
                if (x < 10'000) { return result + 3; }

                x /= 10'000;
                result += 4;
            }

            return result;
        };

        auto const result = digits10(val);
        auto pos          = result - 1;
        while (val >= 10)
        {
            auto const q  = val / 10;
            auto const r  = static_cast<char>(val % 10);
            buffer[pos--] = static_cast<char>('0' + r);
            val           = q;
        }

        *buffer = static_cast<char>(val + '0');
        return buffer;
    }
    default:
    {
        assert(false);
        return buffer;
    }
    }
}

/**
 * @brief Parses the C-string str interpreting its content as an integral number, which is
 * returned as a value of type long int.
 */
constexpr auto atol(const char* str) -> long
{
    constexpr long pow10[19] = {
        // 10000000000000000000UL,
        1000000000000000000UL,
        100000000000000000UL,
        10000000000000000UL,
        1000000000000000UL,
        100000000000000UL,
        10000000000000UL,
        1000000000000UL,
        100000000000UL,
        10000000000UL,
        1000000000UL,
        100000000UL,
        10000000UL,
        1000000UL,
        100000UL,
        10000UL,
        1000UL,
        100UL,
        10UL,
        1UL,
    };

    auto const* first = &str[0];
    auto const* last  = first + etl::strlen(first);

    long result = 0;
    auto i      = sizeof(pow10) / sizeof(pow10[0]) - unsigned(last - first);
    for (; first != last; ++first) { result += pow10[i++] * (*first - '0'); }

    return result;
}
}  // namespace etl

#endif  // TAETL_CSTDLIB_HPP
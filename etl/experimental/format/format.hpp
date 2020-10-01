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

#ifndef TAETL_EXPERIMENTAL_FORMAT_HPP
#define TAETL_EXPERIMENTAL_FORMAT_HPP

#include "etl/array.hpp"
#include "etl/definitions.hpp"
#include "etl/string_view.hpp"
#include "etl/warning.hpp"

namespace etl::experimental::format
{
template <typename Out>
struct format_to_n_result
{
    Out out;
    etl::ptrdiff_t size;
};

template <typename OutputIter, typename... Args>
auto format_to_n(OutputIter out, etl::ptrdiff_t n, etl::string_view fmt,
                 Args const&... args) -> format_to_n_result<OutputIter>
{
    ::etl::ignore_unused(n);
    auto indices = etl::array<size_t, sizeof...(args)> {};
    auto result  = format_to_n_result<OutputIter> {out, 0};

    auto write_char = [&result](auto ch) {
        *result.out++ = ch;
        result.size++;
    };

    auto replace_char_at = [out](auto ch, auto pos) { out[pos] = ch; };

    auto indexCounter = size_t {0};
    for (decltype(fmt)::size_type i {}; i < fmt.size(); ++i)
    {
        auto ch = fmt[i];
        if (ch == '{')
        {
            if (fmt[i + 1] == '{')
            {
                ++i;
                write_char('{');
                continue;
            }

            indices[indexCounter++] = i;
            write_char('0');
            continue;
        }

        if (ch == '}')
        {
            if (fmt[i + 1] == '}')
            {
                ++i;
                write_char('}');
            }
            continue;
        }

        write_char(ch);
    }

    if (indexCounter > 0)
    {
        typename decltype(indices)::size_type i {};
        (replace_char_at(args, indices[i++]), ...);
    }

    return result;
}
}  // namespace etl::experimental::format

#endif  // TAETL_EXPERIMENTAL_FORMAT_HPP

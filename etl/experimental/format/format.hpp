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

#include "etl/cstring.hpp"
#include "etl/definitions.hpp"
#include "etl/iterator.hpp"
#include "etl/string.hpp"
#include "etl/string_view.hpp"
#include "etl/vector.hpp"
#include "etl/warning.hpp"

namespace etl::experimental::format
{
template <class T, class CharT = char>
struct formatter;

template <class OutputIt, class CharT>
struct basic_format_context
{
public:
    using iterator  = OutputIt;
    using char_type = CharT;

    template <typename T>
    using formatter_type = formatter<T, CharT>;

    [[nodiscard]] constexpr auto out() noexcept -> iterator { return pos_; }
    constexpr auto advance_to(iterator it) noexcept -> void { pos_ = it; }

    OutputIt pos_;
};

template <typename ContainerT>
using format_context = basic_format_context<etl::back_insert_iterator<ContainerT>, char>;

template <>
struct formatter<char, char>
{
    template <class FormatContext>
    auto format(char val, FormatContext& fc)
    {
        auto pos = fc.out();
        *pos     = val;
        return pos++;
    }
};

template <>
struct formatter<char const*, char>
{
    template <class FormatContext>
    auto format(char const* val, FormatContext& fc)
    {
        auto pos = fc.out();
        etl::for_each(val, val + etl::strlen(val), [&pos](auto ch) { *pos++ = ch; });
        return pos;
    }
};

template <size_t N>
struct formatter<char[N], char>
{
    template <class FormatContext>
    auto format(char const* val, FormatContext& fc)
    {
        auto pos = fc.out();
        etl::for_each(val, val + N, [&pos](auto ch) { *pos++ = ch; });
        return pos;
    }
};

template <>
struct formatter<etl::string_view, char>
{
    template <typename FormatContext>
    auto format(etl::string_view str, FormatContext& fc)
    {
        auto pos = fc.out();
        for (auto ch : str) { *pos++ = ch; }
        return pos;
    }
};

// template <>
// struct formatter<int, char>
// {
//     template <typename FormatContext>
//     auto format(int val, FormatContext& fc)
//     {
//         auto pos = fc.out();
//         auto str = etl::to_string(val);
//         for (auto ch : str) { *pos++ = ch; }
//         return pos;
//     }
// };

template <typename It>
using diff_t =
    typename ::etl::iterator_traits<::etl::remove_cvref_t<It>>::difference_type;

namespace detail
{
template <typename ValueT, typename Context>
auto format_impl(ValueT const& val, Context& ctx)
{
    auto fmt = formatter<ValueT, char> {};
    fmt.format(val, ctx);
}

template <typename ContextT, typename Pos>
auto parse_format_str(ContextT& ctx, etl::string_view fmt_str, Pos current_pos)
{
    auto pos       = current_pos;
    auto found_arg = false;

    while (!found_arg)
    {
        auto f      = etl::find(begin(fmt_str) + pos, end(fmt_str), '{');
        auto length = static_cast<etl::size_t>(etl::distance(begin(fmt_str) + pos, f));

        format_impl(fmt_str.substr(pos, length), ctx);
        pos += static_cast<etl::size_t>(length + 2);

        if (*etl::next(f) == '{')
        {
            if (auto close = etl::find(f + 2, end(fmt_str), '}');
                *etl::next(close) == '}')
            {
                format_impl('{', ctx);
                auto dist = static_cast<etl::size_t>(etl::distance(f + 2, close));
                format_impl(fmt_str.substr(pos, dist), ctx);
                format_impl('}', ctx);

                pos += static_cast<etl::size_t>(dist + 2);
                continue;
            }
        }

        found_arg = true;
    }

    return pos;
}
}  // namespace detail

template <typename OutputIt, typename... Args>
auto format_to(OutputIt out, etl::string_view fmt, Args const&... args) -> OutputIt
{
    auto ctx         = format_context<::etl::static_string<32>> {out};
    auto current_pos = etl::string_view::size_type {};
    current_pos      = detail::parse_format_str(ctx, fmt, current_pos);

    (
        [&] {
            detail::format_impl(args, ctx);
            current_pos = detail::parse_format_str(ctx, fmt, current_pos);
        }(),
        ...);

    return ctx.out();
}

template <typename Out>
struct format_to_n_result
{
    Out out;
    diff_t<Out> size;
};

template <typename OutputIter, typename... Args>
auto format_to_n(OutputIter out, diff_t<OutputIter> n, ::etl::string_view fmt,
                 Args const&... args) -> format_to_n_result<OutputIter>
{
    ::etl::ignore_unused(n);

    auto indices = ::etl::static_vector<::etl::size_t, sizeof...(args)> {};
    auto result  = format_to_n_result<OutputIter> {out, {}};

    auto write_char = [&result](auto ch) {
        *result.out++ = ch;
        result.size++;
    };

    auto var_start = ::etl::size_t {};
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

            var_start = i;
            continue;
        }

        if (ch == '}')
        {
            if (fmt[i + 1] == '}')
            {
                ++i;
                write_char('}');
                continue;
            }

            indices.push_back(var_start);
            write_char('0');
            continue;
        }

        write_char(ch);
    }

    if (indices.size() > 0)
    {
        [[maybe_unused]] auto replace_char_at = [n](auto output, auto pos, char val) {
            ::etl::ignore_unused(n);
            // assert((long)pos < n);
            output[pos] = val;
        };

        [[maybe_unused]] typename decltype(indices)::size_type i {};
        (replace_char_at(out, indices[i++], args), ...);
    }

    return result;
}
}  // namespace etl::experimental::format

#endif  // TAETL_EXPERIMENTAL_FORMAT_HPP

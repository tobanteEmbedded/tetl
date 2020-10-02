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

template <etl::size_t Capacity>
struct formatter<etl::static_string<Capacity>, char>
{
    template <typename FormatContext>
    auto format(etl::static_string<Capacity> const& str, FormatContext& fc)
    {
        auto pos = fc.out();
        for (auto ch : str) { *pos++ = ch; }
        return pos;
    }
};

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

auto slice_next_argument(etl::string_view str)
    -> etl::pair<etl::string_view, etl::string_view>
{
    using size_type = etl::string_view::size_type;

    constexpr auto token_arg_start = '{';
    constexpr auto token_arg_stop  = '}';

    if (auto res = etl::find(begin(str), end(str), token_arg_start);
        res != end(str) && *etl::next(res) == token_arg_stop)
    {
        auto index = static_cast<size_type>(etl::distance(begin(str), res));
        return etl::make_pair(str.substr(0, index), str.substr(index + 2));
    }

    return etl::make_pair(str, etl::string_view {});
}

}  // namespace detail

template <typename OutputIt, typename... Args>
auto format_to(OutputIt out, etl::string_view fmt, Args const&... args) -> OutputIt
{
    auto ctx = format_context<::etl::static_string<32>> {out};

    auto slices = detail::slice_next_argument(fmt);
    detail::format_impl(slices.first, ctx);
    auto rest = slices.second;
    ::etl::ignore_unused(rest);

    (
        [&] {
            detail::format_impl(args, ctx);
            auto rest_slices = detail::slice_next_argument(rest);
            detail::format_impl(rest_slices.first, ctx);
            rest = rest_slices.second;
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

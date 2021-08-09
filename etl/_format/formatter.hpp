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

#if not defined(TETL_DETAIL_FORMAT_FORMATTER_HPP)
#define TETL_DETAIL_FORMAT_FORMATTER_HPP

#include "etl/_format/context.hpp"

#include "etl/cstdlib.hpp"
#include "etl/numeric.hpp"
#include "etl/string.hpp"

namespace etl {
/// \brief The enabled specializations of formatter define formatting rules for
/// a given type. Enabled specializations meet the Formatter requirements.
///
/// \notes
/// [cppreference.com/w/cpp/utility/format/formatter](https://en.cppreference.com/w/cpp/utility/format/formatter)
/// \group formatter
template <typename T, typename CharT = char>
struct formatter;

/// \brief Standard specializations for basic type char.
/// \group formatter_specialization
template <>
struct formatter<char, char> {
    template <typename FormatContext>
    constexpr auto format(char val, FormatContext& fc) -> decltype(fc.out())
    {
        auto pos = fc.out();
        *pos     = val;
        return pos++;
    }
};

/// \group formatter_specialization
template <>
struct formatter<char const*, char> {
    template <typename FormatContext>
    constexpr auto format(char const* val, FormatContext& fc)
        -> decltype(fc.out())
    {
        return etl::copy(val, val + etl::strlen(val), fc.out());
    }
};

/// \group formatter_specialization
template <::etl::size_t N>
struct formatter<char[N], char> {
    template <typename FormatContext>
    constexpr auto format(char const* val, FormatContext& fc)
        -> decltype(fc.out())
    {
        return etl::copy(val, val + N, fc.out());
    }
};

/// \group formatter_specialization
template <>
struct formatter<etl::string_view, char> {
    template <typename FormatContext>
    constexpr auto format(etl::string_view str, FormatContext& fc)
        -> decltype(fc.out())
    {
        return etl::copy(begin(str), end(str), fc.out());
    }
};

/// \group formatter_specialization
template <etl::size_t Capacity>
struct formatter<etl::static_string<Capacity>, char> {
    template <typename FormatContext>
    constexpr auto format(etl::static_string<Capacity> const& str,
        FormatContext& fc) -> decltype(fc.out())
    {
        return formatter<::etl::string_view>().format(str, fc);
    }
};

namespace detail {
template <typename Integer, typename FormatContext>
constexpr auto integer_format(Integer v, FormatContext& fc)
    -> decltype(fc.out())
{
    char buf[32] {};
    auto res = detail::int_to_ascii(v, begin(buf), 10, sizeof(buf));
    if (res.error == detail::int_to_ascii_error::none) {
        auto str = string_view { begin(buf) };
        return formatter<string_view>().format(str, fc);
    }
    return formatter<string_view>().format("", fc);
}
} // namespace detail
/// \group formatter_specialization
template <>
struct formatter<short, char> {
    template <typename FormatContext>
    constexpr auto format(short v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

/// \group formatter_specialization
template <>
struct formatter<int, char> {
    template <typename FormatContext>
    constexpr auto format(int v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

/// \group formatter_specialization
template <>
struct formatter<long, char> {
    template <typename FormatContext>
    constexpr auto format(long v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

/// \group formatter_specialization
template <>
struct formatter<long long, char> {
    template <typename FormatContext>
    constexpr auto format(long long v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

/// \group formatter_specialization
template <>
struct formatter<unsigned short, char> {
    template <typename FormatContext>
    constexpr auto format(unsigned short v, FormatContext& fc)
        -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

/// \group formatter_specialization
template <>
struct formatter<unsigned, char> {
    template <typename FormatContext>
    constexpr auto format(int v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

/// \group formatter_specialization
template <>
struct formatter<unsigned long, char> {
    template <typename FormatContext>
    constexpr auto format(unsigned long v, FormatContext& fc)
        -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

/// \group formatter_specialization
template <>
struct formatter<unsigned long long, char> {
    template <typename FormatContext>
    constexpr auto format(unsigned long long v, FormatContext& fc)
        -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

} // namespace etl

#endif // TETL_DETAIL_FORMAT_FORMATTER_HPP

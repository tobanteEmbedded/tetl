// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_FORMATTER_HPP
#define TETL_FORMAT_FORMATTER_HPP

#include <etl/_algorithm/copy.hpp>
#include <etl/_cstring/strlen.hpp>
#include <etl/_format/basic_format_context.hpp>
#include <etl/_string/inplace_string.hpp>
#include <etl/_string_view/string_view.hpp>
#include <etl/_strings/from_integer.hpp>

namespace etl {
/// \brief The enabled specializations of formatter define formatting rules for
/// a given type. Enabled specializations meet the Formatter requirements.
///
/// https://en.cppreference.com/w/cpp/utility/format/formatter
template <typename T, typename CharT = char>
struct formatter {
    formatter()                                         = delete;
    formatter(formatter const& other)                   = delete;
    auto operator=(formatter const& other) -> formatter = delete;
};

/// \brief Standard specializations for basic type char.
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

template <>
struct formatter<char const*, char> {
    template <typename FormatContext>
    constexpr auto format(char const* val, FormatContext& fc) -> decltype(fc.out())
    {
        return etl::copy(val, val + etl::strlen(val), fc.out());
    }
};

template <etl::size_t N>
struct formatter<char[N], char> {
    template <typename FormatContext>
    constexpr auto format(char const* val, FormatContext& fc) -> decltype(fc.out())
    {
        return etl::copy(val, val + N, fc.out());
    }
};

template <>
struct formatter<etl::string_view, char> {
    template <typename FormatContext>
    constexpr auto format(etl::string_view str, FormatContext& fc) -> decltype(fc.out())
    {
        return etl::copy(begin(str), end(str), fc.out());
    }
};

template <etl::size_t Capacity>
struct formatter<etl::inplace_string<Capacity>, char> {
    template <typename FormatContext>
    constexpr auto format(etl::inplace_string<Capacity> const& str, FormatContext& fc) -> decltype(fc.out())
    {
        return formatter<etl::string_view>().format(str, fc);
    }
};

namespace detail {
template <typename Integer, typename FormatContext>
constexpr auto integer_format(Integer v, FormatContext& fc) -> decltype(fc.out())
{
    char buf[32]{};
    auto res = strings::from_integer(v, begin(buf), sizeof(buf), 10);
    if (res.error == strings::from_integer_error::none) {
        auto str = string_view{begin(buf)};
        return formatter<string_view>().format(str, fc);
    }
    return formatter<string_view>().format("", fc);
}
} // namespace detail

template <>
struct formatter<short, char> {
    template <typename FormatContext>
    constexpr auto format(short v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

template <>
struct formatter<int, char> {
    template <typename FormatContext>
    constexpr auto format(int v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

template <>
struct formatter<long, char> {
    template <typename FormatContext>
    constexpr auto format(long v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

template <>
struct formatter<long long, char> {
    template <typename FormatContext>
    constexpr auto format(long long v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

template <>
struct formatter<unsigned short, char> {
    template <typename FormatContext>
    constexpr auto format(unsigned short v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

template <>
struct formatter<unsigned, char> {
    template <typename FormatContext>
    constexpr auto format(int v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

template <>
struct formatter<unsigned long, char> {
    template <typename FormatContext>
    constexpr auto format(unsigned long v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

template <>
struct formatter<unsigned long long, char> {
    template <typename FormatContext>
    constexpr auto format(unsigned long long v, FormatContext& fc) -> decltype(fc.out())
    {
        return detail::integer_format(v, fc);
    }
};

} // namespace etl

#endif // TETL_FORMAT_FORMATTER_HPP

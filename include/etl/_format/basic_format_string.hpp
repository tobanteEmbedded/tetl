// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_BASIC_FORMAT_STRING_HPP
#define TETL_FORMAT_BASIC_FORMAT_STRING_HPP

#include <etl/_concepts/convertible_to.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_type_traits/type_identity.hpp>

namespace etl {

template <typename CharT, typename... Args>
struct basic_format_string {
    template <typename T>
        requires convertible_to<T const&, basic_string_view<CharT>>
    consteval basic_format_string(T const& s)
        : _str(s)
    {
    }

    [[nodiscard]] constexpr auto get() const noexcept -> basic_string_view<CharT> { return _str; }

private:
    basic_string_view<CharT> _str;
};

template <typename... Args>
using format_string = basic_format_string<char, type_identity_t<Args>...>;

template <typename... Args>
using wformat_string = basic_format_string<wchar_t, type_identity_t<Args>...>;

} // namespace etl

#endif // TETL_FORMAT_BASIC_FORMAT_STRING_HPP

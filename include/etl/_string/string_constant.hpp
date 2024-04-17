// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRING_STRING_CONSTANT_HPP
#define TETL_STRING_STRING_CONSTANT_HPP

#include <etl/_array/array.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_utility/index_sequence.hpp>

namespace etl {

template <typename CharT, CharT... Chars>
struct string_constant {
    using value_type       = CharT;
    using string_view_type = etl::basic_string_view<CharT>;

    static constexpr auto storage = etl::array<CharT, sizeof...(Chars)>{Chars...};

    static constexpr auto size() noexcept { return storage.size(); }

    static constexpr auto begin() noexcept { return storage.cbegin(); }

    static constexpr auto end() noexcept { return storage.cend(); }

    [[nodiscard]] constexpr operator string_view_type() const noexcept { return {storage.data(), storage.size()}; }
};

template <typename CharT, CharT... Chars>
[[nodiscard]] constexpr auto
operator==(string_constant<CharT, Chars...> /*lhs*/, string_constant<CharT, Chars...> /*rhs*/) noexcept -> bool
{
    return true;
}

template <typename CharT, CharT... CharsL, CharT... CharsR>
[[nodiscard]] constexpr auto
operator==(string_constant<CharT, CharsL...> /*lhs*/, string_constant<CharT, CharsR...> /*rhs*/) noexcept -> bool
{
    return false;
}

namespace detail {

template <auto CharArray>
    requires(etl::size(CharArray) > 0)
consteval auto to_string_constant()
{
    return []<etl::size_t... Is>(etl::index_sequence<Is...> /*i*/) {
        return etl::string_constant<char, etl::get<Is>(CharArray)...>{};
    }(etl::make_index_sequence<etl::size(CharArray) - 1>{});
}

} // namespace detail

} // namespace etl

#define TETL_STRING_C(str) etl::detail::to_string_constant<etl::to_array(str)>()

#endif // TETL_STRING_STRING_CONSTANT_HPP

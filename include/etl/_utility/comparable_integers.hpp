// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_COMPARABLE_INTEGERS_HPP
#define TETL_UTILITY_COMPARABLE_INTEGERS_HPP

#include <etl/_type_traits/is_same.hpp>

namespace etl::detail {

template <typename T>
concept integer_and_not_char =              //
    etl::is_integral_v<T>                   //
    and (                                   //
        not etl::is_same_v<T, bool>         //
        and not etl::is_same_v<T, char>     //
        and not etl::is_same_v<T, char16_t> //
        and not etl::is_same_v<T, char32_t> //
        and not etl::is_same_v<T, wchar_t>  //
    );

template <typename T, typename U>
concept comparable_integers = integer_and_not_char<T> and integer_and_not_char<U>;

} // namespace etl::detail

#endif // TETL_UTILITY_COMPARABLE_INTEGERS_HPP

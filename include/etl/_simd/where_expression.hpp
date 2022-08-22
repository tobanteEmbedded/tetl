/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_SIMD_WHERE_EXPRESSION_HPP
#define TETL_SIMD_WHERE_EXPRESSION_HPP

#include "etl/_simd/const_where_expression.hpp"

namespace etl {

template <typename M, typename T>
struct where_expression : const_where_expression<M, T> {
    template <typename U>
    auto operator=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator+=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator-=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator*=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator/=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator%=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator&=(U&& x) && noexcept -> void;

    template <typename U>
    auto operator|=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator^=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator<<=(U&& x) && noexcept -> void;
    template <typename U>
    auto operator>>=(U&& x) && noexcept -> void;

    auto operator++() && noexcept -> void;
    auto operator++(int) && noexcept -> void;
    auto operator--() && noexcept -> void;
    auto operator--(int) && noexcept -> void;

    template <typename U, typename Flags>
    auto copy_from(U const* mem, Flags) && -> void;
};

} // namespace etl

#endif // TETL_SIMD_WHERE_EXPRESSION_HPP

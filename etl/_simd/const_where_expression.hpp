/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_SIMD_CONST_WHERE_EXPRESSION_HPP
#define TETL_SIMD_CONST_WHERE_EXPRESSION_HPP

namespace etl {

template <typename M, typename T>
struct const_where_expression {
    const_where_expression(const_where_expression const&)            = delete;
    const_where_expression& operator=(const_where_expression const&) = delete;

    auto operator-() const&& noexcept -> T;
    auto operator+() const&& noexcept -> T;
    auto operator~() const&& noexcept -> T;

    template <typename U, typename Flags>
    auto copy_to(U* mem, Flags f) const&& -> void;

private:
    M const _mask;
    T& _data;
};

} // namespace etl

#endif // TETL_SIMD_CONST_WHERE_EXPRESSION_HPP
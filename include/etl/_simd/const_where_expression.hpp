// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SIMD_CONST_WHERE_EXPRESSION_HPP
#define TETL_SIMD_CONST_WHERE_EXPRESSION_HPP

namespace etl {

template <typename M, typename T>
struct const_where_expression {
    const_where_expression(const_where_expression const&)                    = delete;
    auto operator=(const_where_expression const&) -> const_where_expression& = delete;

    auto operator-() const&& noexcept -> T;
    auto operator+() const&& noexcept -> T;
    auto operator~() const&& noexcept -> T;

    template <typename U, typename Flags>
    auto copy_to(U* mem, Flags f) const&& -> void;

private:
    M const mask_;
    T& data_;
};

} // namespace etl

#endif // TETL_SIMD_CONST_WHERE_EXPRESSION_HPP

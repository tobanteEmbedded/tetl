// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_FORWARD_LIKE_HPP
#define TETL_UTILITY_FORWARD_LIKE_HPP

#include <etl/_type_traits/is_const.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/as_const.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

template <typename T, typename U>
[[nodiscard]] constexpr auto&& forward_like(U&& x) noexcept
{
    constexpr auto is_adding_const = etl::is_const_v<etl::remove_reference_t<T>>;

    if constexpr (etl::is_lvalue_reference_v<T&&>) {
        if constexpr (is_adding_const)
            return etl::as_const(x);
        else
            return static_cast<U&>(x);
    } else {
        if constexpr (is_adding_const)
            return TETL_MOVE(etl::as_const(x));
        else
            return TETL_MOVE(x);
    }
}

} // namespace etl

#endif // TETL_UTILITY_FORWARD_LIKE_HPP

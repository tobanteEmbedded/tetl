// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_MOVE_HPP
#define TETL_UTILITY_MOVE_HPP

#include <etl/_type_traits/remove_reference.hpp>

namespace etl {

/// \brief move is used to indicate that an object t may be "moved from",
/// i.e. allowing the efficient transfer of resources from t to another object.
/// In particular, move produces an xvalue expression that identifies its
/// argument t. It is exactly equivalent to a static_cast to an rvalue reference
/// type.
///
/// \returns `static_cast<remove_reference_t<T>&&>(t)`
template <typename T>
constexpr auto move(T&& t) noexcept -> etl::remove_reference_t<T>&&
{
    return static_cast<etl::remove_reference_t<T>&&>(t);
}

} // namespace etl

// https://www.foonathan.net/2020/09/move-forward
#define TETL_MOVE(...) static_cast<etl::remove_reference_t<decltype(__VA_ARGS__)>&&>(__VA_ARGS__)

#endif // TETL_UTILITY_MOVE_HPP

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_TO_ADDRESS_HPP
#define TETL_MEMORY_TO_ADDRESS_HPP

#include "etl/_memory/pointer_traits.hpp"
#include "etl/_type_traits/is_function.hpp"

namespace etl {

/// \brief Obtain the address represented by p without forming a reference to
/// the object pointed to by p.
///
/// \details Fancy pointer overload: If the expression
/// pointer_traits<Ptr>::to_address(p) is well-formed, returns the result of
/// that expression. Otherwise, returns to_address(p.operator->()).
template <typename Ptr>
constexpr auto to_address(Ptr const& ptr) noexcept
{
    if constexpr (requires { pointer_traits<Ptr>::to_address(ptr); }) {
        return pointer_traits<Ptr>::to_address(ptr);
    } else {
        return to_address(ptr.operator->());
    }
}

/// \brief Obtain the address represented by p without forming a reference to
/// the object pointed to by p.
///
/// \details Raw pointer overload: If T is a function type, the program is
/// ill-formed. Otherwise, returns p unmodified.
template <typename T>
    requires(not is_function_v<T>)
constexpr auto to_address(T* ptr) noexcept -> T*
{
    return ptr;
}

} // namespace etl

#endif // TETL_MEMORY_TO_ADDRESS_HPP

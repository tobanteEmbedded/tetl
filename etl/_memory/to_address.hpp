/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_TO_ADDRESS_HPP
#define TETL_MEMORY_TO_ADDRESS_HPP

#include "etl/_memory/pointer_traits.hpp"
#include "etl/_type_traits/is_function.hpp"

namespace etl {

namespace detail {
template <typename T>
constexpr auto to_address_impl(T* ptr) noexcept -> T*
{
    static_assert(!is_function_v<T>);
    return ptr;
}

template <typename Ptr>
constexpr auto to_address_impl(Ptr const& ptr) noexcept -> decltype(pointer_traits<Ptr>::to_address(ptr))
{
    return pointer_traits<Ptr>::to_address(ptr);
}

template <typename Ptr, typename... Ignore>
constexpr auto to_address_impl(Ptr const& ptr, Ignore... /*ignore*/) noexcept
{
    return to_address_impl(ptr.operator->());
}
} // namespace detail

/// \brief Obtain the address represented by p without forming a reference to
/// the object pointed to by p.
///
/// \details Fancy pointer overload: If the expression
/// pointer_traits<Ptr>::to_address(p) is well-formed, returns the result of
/// that expression. Otherwise, returns to_address(p.operator->()).
template <typename Ptr>
constexpr auto to_address(Ptr const& ptr) noexcept
{
    return detail::to_address_impl(ptr);
}

/// \brief Obtain the address represented by p without forming a reference to
/// the object pointed to by p.
///
/// \details Raw pointer overload: If T is a function type, the program is
/// ill-formed. Otherwise, returns p unmodified.
template <typename T>
constexpr auto to_address(T* ptr) noexcept -> T*
{
    return detail::to_address_impl(ptr);
}

} // namespace etl

#endif // TETL_MEMORY_TO_ADDRESS_HPP
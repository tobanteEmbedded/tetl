/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_ADDRESSOF_HPP
#define TETL_MEMORY_ADDRESSOF_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_object.hpp"

namespace etl {

/// \brief Obtains the actual address of the object or function arg, even in
/// presence of overloaded operator&.
/// \group addressof
template <typename T>
auto addressof(T& arg) noexcept -> enable_if_t<is_object_v<T>, T*>
{
    return TETL_BUILTIN_ADDRESSOF(arg);
}

/// \group addressof
template <typename T>
auto addressof(T& arg) noexcept -> enable_if_t<!is_object_v<T>, T*>
{
    return &arg;
}

/// \group addressof
template <typename T>
auto addressof(T const&& /*ignore*/) = delete;

} // namespace etl

#endif // TETL_MEMORY_ADDRESSOF_HPP
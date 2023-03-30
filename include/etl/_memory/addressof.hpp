/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_ADDRESSOF_HPP
#define TETL_MEMORY_ADDRESSOF_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/is_object.hpp>

namespace etl {

/// \brief Obtains the actual address of the object or function arg, even in
/// presence of overloaded operator&.
template <typename T>
    requires(is_object_v<T>)
constexpr auto addressof(T& arg) noexcept -> T*
{
    return __builtin_addressof(arg);
}

template <typename T>
    requires(not is_object_v<T>)
constexpr auto addressof(T& arg) noexcept -> T*
{
    return &arg;
}

template <typename T>
auto addressof(T const&& /*ignore*/) = delete;

} // namespace etl

#endif // TETL_MEMORY_ADDRESSOF_HPP

/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ITERATOR_DATA_HPP
#define TETL_ITERATOR_DATA_HPP

namespace etl {

/// \brief Returns a pointer to the block of memory containing the elements of
/// the container.
template <typename C>
constexpr auto data(C& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
    return c.data();
}

template <typename C>
constexpr auto data(C const& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
    return c.data();
}

template <typename T, size_t N>
constexpr auto data(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

} // namespace etl

#endif // TETL_ITERATOR_DATA_HPP
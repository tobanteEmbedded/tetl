// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ITERATOR_DATA_HPP
#define TETL_ITERATOR_DATA_HPP

namespace etl {

/// Returns a pointer to the block of memory containing the elements of the container.
/// \ingroup iterator
template <typename C>
constexpr auto data(C& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
    return c.data();
}

/// \ingroup iterator
template <typename C>
constexpr auto data(C const& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
    return c.data();
}

/// \ingroup iterator
template <typename T, size_t N>
constexpr auto data(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

} // namespace etl

#endif // TETL_ITERATOR_DATA_HPP

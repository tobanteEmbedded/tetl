// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_SIZE_HPP
#define TETL_ITERATOR_SIZE_HPP

#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/common_type.hpp>
#include <etl/_type_traits/make_signed.hpp>
#include <etl/_warning/ignore_unused.hpp>

namespace etl {

/// \brief Returns the size of the given container c or array array. Returns
/// c.size(), converted to the return type if necessary.
template <typename C>
constexpr auto size(C const& c) noexcept(noexcept(c.size())) -> decltype(c.size())
{
    return c.size();
}

template <typename T, size_t N>
constexpr auto size(T const (&array)[N]) noexcept -> size_t
{
    etl::ignore_unused(&array[0]);
    return N;
}

template <typename C>
constexpr auto ssize(C const& c) -> common_type_t<ptrdiff_t, make_signed_t<decltype(c.size())>>
{
    using R = common_type_t<ptrdiff_t, make_signed_t<decltype(c.size())>>;
    return static_cast<R>(c.size());
}

template <typename T, ptrdiff_t N>
constexpr auto ssize(T const (&array)[static_cast<size_t>(N)]) noexcept -> ptrdiff_t
{
    // The static_cast<size_t>(N) inside the array parameter is to keep gcc's
    // sign-conversion warnings happy. Array sizes are of type size_t which
    // triggers a signed to unsigned conversion in this case.
    etl::ignore_unused(&array[0]);
    return N;
}

} // namespace etl

#endif // TETL_ITERATOR_SIZE_HPP

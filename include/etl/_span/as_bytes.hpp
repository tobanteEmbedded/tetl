// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SPAN_AS_BYTES_HPP
#define TETL_SPAN_AS_BYTES_HPP

#include <etl/_cstddef/byte.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/is_const.hpp>

namespace etl {

namespace detail {
template <typename T, etl::size_t N>
inline constexpr etl::size_t span_as_bytes_size = N == etl::dynamic_extent ? etl::dynamic_extent : sizeof(T) * N;
}

/// \brief Obtains a view to the object representation of the elements of the
/// span s.
///
/// \details If N is dynamic_extent, the extent of the returned span S is also
/// dynamic_extent; otherwise it is sizeof(T) * N.
template <typename T, size_t N>
[[nodiscard]] auto as_bytes(span<T, N> s) noexcept -> span<byte const, detail::span_as_bytes_size<T, N>>
{
    return {reinterpret_cast<byte const*>(s.data()), s.size_bytes()};
}

/// \brief Obtains a view to the object representation of the elements of the
/// span s.
///
/// \details If N is dynamic_extent, the extent of the returned span S is also
/// dynamic_extent; otherwise it is sizeof(T) * N. Only participates in overload
/// resolution if is_const_v<T> is false.
template <typename T, size_t N>
    requires(not is_const_v<T>)
[[nodiscard]] auto as_writable_bytes(span<T, N> s) noexcept -> span<byte, detail::span_as_bytes_size<T, N>>
{
    return {reinterpret_cast<byte*>(s.data()), s.size_bytes()};
}

} // namespace etl

#endif // TETL_SPAN_AS_BYTES_HPP

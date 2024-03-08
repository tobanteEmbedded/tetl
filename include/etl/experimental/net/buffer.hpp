// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_NET_BUFFER_HPP
#define TETL_NET_BUFFER_HPP

#include <etl/version.hpp>

#include <etl/array.hpp>
#include <etl/vector.hpp>

#include <etl/experimental/net/buffer_const.hpp>
#include <etl/experimental/net/buffer_mutable.hpp>

namespace etl::experimental::net {
inline auto make_buffer(void* data, size_t size) noexcept -> mutable_buffer { return mutable_buffer {data, size}; }

inline auto make_buffer(void const* data, size_t size) noexcept -> const_buffer { return const_buffer {data, size}; }

template <typename T, etl::size_t Size>
inline auto make_buffer(etl::array<T, Size>& array) noexcept -> mutable_buffer
{
    return mutable_buffer {array.data(), array.size()};
}

template <typename T, etl::size_t Size>
inline auto make_buffer(etl::array<T, Size> const& array) noexcept -> const_buffer
{
    return const_buffer {array.data(), array.size()};
}

template <typename T, etl::size_t Size>
inline auto make_buffer(etl::static_vector<T, Size>& vec) noexcept -> mutable_buffer
{
    return mutable_buffer {vec.data(), vec.size()};
}

template <typename T, etl::size_t Size>
inline auto make_buffer(etl::static_vector<T, Size> const& vec) noexcept -> const_buffer
{
    return const_buffer {vec.data(), vec.size()};
}

} // namespace etl::experimental::net

#endif // TETL_NET_BUFFER_HPP

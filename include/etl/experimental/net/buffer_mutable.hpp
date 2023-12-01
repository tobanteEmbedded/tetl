// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_NET_BUFFER_MUTABLE_HPP
#define TETL_NET_BUFFER_MUTABLE_HPP

#include "etl/version.hpp"

#include "etl/array.hpp"
#include "etl/cstddef.hpp"

namespace etl::experimental::net {
struct mutable_buffer {
    /// \brief Construct an empty buffer.
    mutable_buffer() noexcept = default;

    /// \brief Construct a buffer to represent a given memory range.
    mutable_buffer(void* data, etl::size_t size) : _data { data }, _size { size } { }

    /// \brief Get a pointer to the beginning of the memory range.
    [[nodiscard]] auto data() const noexcept -> void* { return _data; }

    /// \brief Get the size of the memory range.
    [[nodiscard]] auto size() const noexcept -> etl::size_t { return _size; }

    /// \brief Move the start of the buffer by the specified number of bytes.
    auto operator+=(etl::size_t n) noexcept -> mutable_buffer&
    {
        auto const offset = n < _size ? n : _size;
        _data             = static_cast<char*>(_data) + offset;
        _size -= offset;
        return *this;
    }

private:
    void* _data       = nullptr;
    etl::size_t _size = 0;
};

/// \brief Create a new modifiable buffer that is offset from the start of
/// another.
/// \relates mutable_buffer
inline auto operator+(mutable_buffer const& b, etl::size_t const n) noexcept -> mutable_buffer
{
    auto offset = n < b.size() ? n : b.size();
    auto* data  = static_cast<char*>(b.data()) + offset;
    auto size   = b.size() - offset;
    return mutable_buffer { data, size };
}

/// \brief Create a new modifiable buffer that is offset from the start of
/// another.
/// \relates mutable_buffer
inline auto operator+(etl::size_t const n, mutable_buffer const& b) noexcept -> mutable_buffer { return b + n; }

} // namespace etl::experimental::net

#endif // TETL_NET_BUFFER_MUTABLE_HPP

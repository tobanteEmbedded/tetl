// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MEMORY_MONOTONIC_ALLOCATOR_HPP
#define TETL_MEMORY_MONOTONIC_ALLOCATOR_HPP

#include <etl/_cstddef/byte.hpp>
#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_memory/align.hpp>
#include <etl/_span/span.hpp>

namespace etl {
template <typename T>
struct monotonic_allocator {
    using value_type      = T;
    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;

    explicit monotonic_allocator(etl::span<etl::byte> memory)
        : _memory{memory}
    {
    }

    [[nodiscard]] auto allocate(etl::size_t n) -> T*
    {
        if (etl::align(alignof(T), sizeof(T) * n, _ptr, _sz) != nullptr) {
            auto* result = reinterpret_cast<T*>(_ptr);
            _ptr         = reinterpret_cast<char*>(_ptr) + sizeof(T) * n;
            _sz -= sizeof(T) * n;
            return result;
        }
        return nullptr;
    }

    auto deallocate(T* p, etl::size_t n) -> void
    {
        etl::ignore_unused(p, n);
    }

private:
    etl::span<etl::byte> _memory;
    void* _ptr{_memory.data()};
    etl::size_t _sz{_memory.size()};
};

} // namespace etl

#endif // TETL_MEMORY_MONOTONIC_ALLOCATOR_HPP

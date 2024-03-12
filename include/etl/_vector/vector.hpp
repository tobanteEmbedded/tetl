// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VECTOR_VECTOR_HPP
#define TETL_VECTOR_VECTOR_HPP

#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_memory/allocator_traits.hpp>
#include <etl/_memory/destroy.hpp>
#include <etl/_memory/uninitialized_fill.hpp>
#include <etl/_utility/exchange.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

template <typename T, typename Allocator>
struct vector {
    using value_type      = T;
    using allocator_type  = Allocator;
    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;
    using reference       = T&;
    using const_reference = T const&;
    using iterator        = T*;
    using const_iterator  = T const*;

    constexpr vector() = default;

    explicit constexpr vector(Allocator alloc) : _alloc{etl::move(alloc)} { }

    constexpr vector(etl::size_t n, T const& value, Allocator alloc = Allocator()) : _alloc{etl::move(alloc)}
    {
        allocate_and_fill(n, value);
    }

    explicit constexpr vector(etl::size_t n, Allocator alloc = Allocator()) : vector{n, T(), etl::move(alloc)} { }

    constexpr vector(vector const& o)                    = delete;
    constexpr auto operator=(vector const& o) -> vector& = delete;

    constexpr vector(vector&& other) noexcept
        : _ptr{etl::exchange(other._ptr, nullptr)}
        , _size{etl::exchange(other._size, 0)}
        , _capacity{etl::exchange(other._capacity, 0)}
        , _alloc{etl::exchange(other._alloc, Allocator{})}
    {
    }

    constexpr auto operator=(vector&& other) noexcept -> vector&
    {
        _ptr      = etl::exchange(other._ptr, nullptr);
        _size     = etl::exchange(other._size, 0);
        _capacity = etl::exchange(other._capacity, 0);
        _alloc    = etl::exchange(other._alloc, Allocator{});
        return *this;
    }

    constexpr ~vector() noexcept
    {
        clear();
        if (_ptr != nullptr) {
            deallocate();
        }
    }

    [[nodiscard]] constexpr auto data() -> T* { return _ptr; }

    [[nodiscard]] constexpr auto data() const -> T const* { return _ptr; }

    [[nodiscard]] constexpr auto begin() -> T* { return _ptr; }

    [[nodiscard]] constexpr auto begin() const -> T const* { return _ptr; }

    [[nodiscard]] constexpr auto end() -> T* { return etl::next(_ptr, etl::ptrdiff_t(size())); }

    [[nodiscard]] constexpr auto end() const -> T const* { return etl::next(_ptr, etl::ptrdiff_t(size())); }

    [[nodiscard]] constexpr auto empty() -> bool { return size() == 0; }

    [[nodiscard]] constexpr auto empty() const -> bool { return size() == 0; }

    [[nodiscard]] constexpr auto size() -> etl::size_t { return _size; }

    [[nodiscard]] constexpr auto size() const -> etl::size_t { return _size; }

    [[nodiscard]] constexpr auto capacity() -> etl::size_t { return _capacity; }

    [[nodiscard]] constexpr auto capacity() const -> etl::size_t { return _capacity; }

    constexpr auto clear() noexcept -> void
    {
        etl::destroy(begin(), end());
        _size = 0;
    }

    friend constexpr auto swap(vector& lhs, vector& rhs) -> void
    {
        etl::swap(lhs._ptr, rhs._ptr);
        etl::swap(lhs._size, rhs._size);
        etl::swap(lhs._capacity, rhs._capacity);
        swap(lhs._alloc, rhs._alloc);
    }

private:
    constexpr auto allocate_and_fill(etl::size_t n, T const& value) -> void
    {
        _ptr      = etl::allocator_traits<Allocator>::allocate(_alloc, n);
        _size     = n;
        _capacity = n;
        etl::uninitialized_fill(begin(), end(), value);
    }

    constexpr auto deallocate() -> void { etl::allocator_traits<Allocator>::deallocate(_alloc, _ptr, capacity()); }

    T* _ptr{nullptr};
    etl::size_t _size{0};
    etl::size_t _capacity{0};
    TETL_NO_UNIQUE_ADDRESS Allocator _alloc;
};

} // namespace etl

#endif // TETL_VECTOR_VECTOR_HPP

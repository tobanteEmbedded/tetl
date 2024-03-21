// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_INPLACE_VECTOR_INPLACE_VECTOR_HPP
#define TETL_INPLACE_VECTOR_INPLACE_VECTOR_HPP

#include <etl/_config/all.hpp>

#include <etl/_algorithm/copy.hpp>
#include <etl/_algorithm/move.hpp>
#include <etl/_array/uninitialized_array.hpp>
#include <etl/_container/smallest_size_t.hpp>
#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_memory/destroy.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_nothrow_copy_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_trivially_copy_constructible.hpp>
#include <etl/_type_traits/is_trivially_destructible.hpp>
#include <etl/_type_traits/is_trivially_move_constructible.hpp>
#include <etl/_utility/exchange.hpp>

namespace etl {

template <typename T, etl::size_t Capacity>
struct inplace_vector {
    using value_type             = T;
    using size_type              = etl::size_t;
    using difference_type        = etl::ptrdiff_t;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using pointer                = T*;
    using const_pointer          = T const*;
    using iterator               = T*;
    using const_iterator         = T const*;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    constexpr inplace_vector() = default;

    inplace_vector(inplace_vector const& other)
        requires(Capacity == 0 or etl::is_trivially_copy_constructible_v<T>)
    = default;

    constexpr inplace_vector(inplace_vector const& other) noexcept(etl::is_nothrow_copy_constructible_v<T>)
    {
        etl::copy(other.begin(), other.end(), begin());
        _size = other._size; // NOLINT(cppcoreguidelines-prefer-member-initializer)
    }

    inplace_vector(inplace_vector&& other)
        requires(Capacity == 0 or etl::is_trivially_move_constructible_v<T>)
    = default;

    constexpr inplace_vector(inplace_vector&& other) noexcept(etl::is_nothrow_move_constructible_v<T>)
    {
        etl::move(other.begin(), other.end(), begin());
        _size = etl::exchange(other._size, internal_size_t{}); // NOLINT(cppcoreguidelines-prefer-member-initializer)
    }

    ~inplace_vector()
        requires(Capacity == 0 or etl::is_trivially_destructible_v<T>)
    = default;

    constexpr ~inplace_vector() { etl::destroy(begin(), end()); }

    [[nodiscard]] constexpr auto begin() const noexcept -> T const* { return data(); }

    [[nodiscard]] constexpr auto begin() noexcept -> T* { return data(); }

    [[nodiscard]] constexpr auto end() const noexcept -> T const*
    {
        return etl::next(begin(), static_cast<etl::ptrdiff_t>(size()));
    }

    [[nodiscard]] constexpr auto end() noexcept -> T*
    {
        return etl::next(begin(), static_cast<etl::ptrdiff_t>(size()));
    }

    [[nodiscard]] constexpr auto data() const noexcept -> T const* { return _storage.data(); }

    [[nodiscard]] constexpr auto data() noexcept -> T* { return _storage.data(); }

    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == 0; }

    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t { return static_cast<etl::size_t>(_size); }

    [[nodiscard]] static constexpr auto capacity() noexcept -> etl::size_t { return Capacity; }

    [[nodiscard]] static constexpr auto max_size() noexcept -> etl::size_t { return Capacity; }

private:
    struct empty_size_t {
        template <typename Int>
        constexpr operator Int() const noexcept
        {
            return 0;
        }
    };

    using internal_size_t = etl::conditional_t<Capacity == 0, empty_size_t, etl::smallest_size_t<Capacity>>;
    TETL_NO_UNIQUE_ADDRESS etl::uninitialized_array<T, Capacity> _storage;
    TETL_NO_UNIQUE_ADDRESS internal_size_t _size;
};

template <typename T>
struct inplace_vector<T, 0> {
    using value_type             = T;
    using size_type              = etl::size_t;
    using difference_type        = etl::ptrdiff_t;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using pointer                = T*;
    using const_pointer          = T const*;
    using iterator               = T*;
    using const_iterator         = T const*;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    constexpr inplace_vector() = default;

    [[nodiscard]] constexpr auto begin() const noexcept -> T const* { return data(); }

    [[nodiscard]] constexpr auto begin() noexcept -> T* { return data(); }

    [[nodiscard]] constexpr auto end() const noexcept -> T const* { return nullptr; }

    [[nodiscard]] constexpr auto end() noexcept -> T* { return nullptr; }

    [[nodiscard]] constexpr auto data() const noexcept -> T const* { return nullptr; }

    [[nodiscard]] constexpr auto data() noexcept -> T* { return nullptr; }

    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == 0; }

    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t { return 0; }

    [[nodiscard]] static constexpr auto capacity() noexcept -> etl::size_t { return 0; }

    [[nodiscard]] static constexpr auto max_size() noexcept -> etl::size_t { return 0; }
};

} // namespace etl

#endif // TETL_INPLACE_VECTOR_INPLACE_VECTOR_HPP

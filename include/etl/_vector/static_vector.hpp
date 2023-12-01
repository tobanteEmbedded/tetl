// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VECTOR_STATIC_VECTOR_HPP
#define TETL_VECTOR_STATIC_VECTOR_HPP

#include "etl/_algorithm/equal_range.hpp"
#include "etl/_algorithm/find.hpp"
#include "etl/_algorithm/generate_n.hpp"
#include "etl/_algorithm/move.hpp"
#include "etl/_algorithm/remove_if.hpp"
#include "etl/_algorithm/rotate.hpp"
#include "etl/_algorithm/transform.hpp"
#include "etl/_array/array.hpp"
#include "etl/_array/c_array.hpp"
#include "etl/_cassert/macro.hpp"
#include "etl/_concepts/same_as.hpp"
#include "etl/_container/index.hpp"
#include "etl/_container/smallest_size_t.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_functional/is_transparent.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/data.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_iterator/rbegin.hpp"
#include "etl/_iterator/rend.hpp"
#include "etl/_iterator/size.hpp"
#include "etl/_new/operator.hpp"
#include "etl/_type_traits/aligned_storage.hpp"
#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/is_assignable.hpp"
#include "etl/_type_traits/is_const.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_copy_constructible.hpp"
#include "etl/_type_traits/is_nothrow_destructible.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_pointer.hpp"
#include "etl/_type_traits/is_trivial.hpp"

namespace etl {
namespace detail {
/// \brief Storage for zero elements.
template <typename T>
struct static_vector_zero_storage {
    using size_type       = uint8_t;
    using value_type      = T;
    using difference_type = ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;

    /// \brief Defaulted constructor.
    constexpr static_vector_zero_storage() = default;

    /// \brief Defaulted copy constructor.
    constexpr static_vector_zero_storage(static_vector_zero_storage const&) = default;

    /// \brief Defaulted copy assignment .
    constexpr auto operator=(static_vector_zero_storage const&) noexcept -> static_vector_zero_storage& = default;

    /// \brief Defaulted move constructor.
    constexpr static_vector_zero_storage(static_vector_zero_storage&&) noexcept = default;

    /// \brief Defaulted move assignment.
    constexpr auto operator=(static_vector_zero_storage&&) noexcept -> static_vector_zero_storage& = default;

    /// \brief Defaulted destructor.
    ~static_vector_zero_storage() = default;

    /// \brief Pointer to the data in the storage.
    [[nodiscard]] static constexpr auto data() noexcept -> pointer { return nullptr; }

    /// \brief Number of elements currently stored.
    [[nodiscard]] static constexpr auto size() noexcept -> size_type { return 0; }

    /// \brief Capacity of the storage.
    [[nodiscard]] static constexpr auto capacity() noexcept -> size_type { return 0; }

    /// \brief Is the storage empty?
    [[nodiscard]] static constexpr auto empty() noexcept -> bool { return true; }

    /// \brief Is the storage full?
    [[nodiscard]] static constexpr auto full() noexcept -> bool { return true; }

    /// \brief Constructs a new element at the end of the storagein-place.
    /// Increases size of the storage by one. Always fails for empty
    /// storage.
    template <typename... Args>
        requires(is_constructible_v<T, Args...>)
    static constexpr auto emplace_back(Args&&... /*unused*/) noexcept -> void
    {
        TETL_ASSERT(false);
    }

    /// \brief Removes the last element of the storage. Always fails for
    /// empty storage.
    static constexpr void pop_back() noexcept { TETL_ASSERT(false); }

protected:
    /// \brief Changes the size of the storage without adding or removing
    /// elements (unsafe). The size of an empty storage can only be changed
    /// to 0.
    static constexpr void unsafe_set_size([[maybe_unused]] size_t newSize) noexcept { TETL_ASSERT(newSize == 0); }

    /// \brief Destroys all elements of the storage in range [begin, end)
    /// without changings its size (unsafe). Nothing to destroy since the
    /// storage is empty.
    template <typename InputIt>
    static constexpr auto unsafe_destroy(InputIt /* begin */, InputIt /* end */) noexcept -> void
    {
    }

    /// \brief Destroys all elements of the storage without changing its
    /// size (unsafe). Nothing to destroy since the storage is empty.
    static constexpr void unsafe_destroy_all() noexcept { }
};

/// \brief Storage for trivial types.
template <typename T, size_t Capacity>
struct static_vector_trivial_storage {
    static_assert(etl::is_trivial_v<T>);
    static_assert(Capacity != size_t {0});

    using size_type       = etl::smallest_size_t<Capacity>;
    using value_type      = T;
    using difference_type = ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;

    constexpr static_vector_trivial_storage() noexcept = default;

    constexpr static_vector_trivial_storage(static_vector_trivial_storage const&) noexcept                    = default;
    constexpr auto operator=(static_vector_trivial_storage const&) noexcept -> static_vector_trivial_storage& = default;

    constexpr static_vector_trivial_storage(static_vector_trivial_storage&&) noexcept                    = default;
    constexpr auto operator=(static_vector_trivial_storage&&) noexcept -> static_vector_trivial_storage& = default;

    ~static_vector_trivial_storage() = default;

    /// \brief Direct access to the underlying storage.
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer { return _data.data(); }

    /// \brief Direct access to the underlying storage.
    [[nodiscard]] constexpr auto data() noexcept -> pointer { return _data.data(); }

    /// \brief Number of elements in the storage.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return _size; }

    /// \brief Maximum number of elements that can be allocated in the
    /// storage.
    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type { return Capacity; }

    /// \brief Is the storage empty?
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == size_type {0}; }

    /// \brief Is the storage full?
    [[nodiscard]] constexpr auto full() const noexcept -> bool { return size() == Capacity; }

    /// \brief Constructs an element in-place at the end of the storage.
    template <typename... Args>
        requires(is_constructible_v<T, Args...> && is_assignable_v<value_type&, T>)
    constexpr auto emplace_back(Args&&... args) noexcept -> void
    {
        TETL_ASSERT(!full());
        index(_data, size()) = T(forward<Args>(args)...);
        unsafe_set_size(static_cast<size_type>(size()) + 1U);
    }

    /// \brief Remove the last element from the container.
    constexpr auto pop_back() noexcept -> void
    {
        TETL_ASSERT(!empty());
        unsafe_set_size(static_cast<size_type>(size() - 1));
    }

protected:
    /// \brief (unsafe) Changes the container size to new_size.
    ///
    /// \warning No elements are constructed or destroyed.
    constexpr auto unsafe_set_size(size_t newSize) noexcept -> void
    {
        TETL_ASSERT(newSize <= Capacity);
        _size = size_type(newSize);
    }

    /// \brief (unsafe) Destroy elements in the range [begin, end).
    ///
    /// \warning The size of the storage is not changed.
    template <typename InputIt>
    constexpr auto unsafe_destroy(InputIt /*unused*/, InputIt /*unused*/) noexcept -> void
    {
    }

    /// \brief (unsafe) Destroys all elements of the storage.
    ///
    /// \warning The size of the storage is not changed.
    constexpr auto unsafe_destroy_all() noexcept -> void { }

private:
    // If the value_type is const, make a const array of
    // non-const elements:
    using data_t = conditional_t<!is_const_v<T>, array<T, Capacity>, array<remove_const_t<T>, Capacity> const>;
    alignas(alignof(T)) data_t _data {};

    size_type _size = 0;
};

/// \brief Storage for non-trivial elements.
template <typename T, size_t Capacity>
struct static_vector_non_trivial_storage {
    static_assert(!is_trivial_v<T>);
    static_assert(Capacity != size_t {0});

    using size_type       = etl::smallest_size_t<Capacity>;
    using value_type      = T;
    using difference_type = ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;

    static_vector_non_trivial_storage() = default;

    static_vector_non_trivial_storage(static_vector_non_trivial_storage const&)                    = default;
    auto operator=(static_vector_non_trivial_storage const&) -> static_vector_non_trivial_storage& = default;

    static_vector_non_trivial_storage(static_vector_non_trivial_storage&&) noexcept                    = default;
    auto operator=(static_vector_non_trivial_storage&&) noexcept -> static_vector_non_trivial_storage& = default;

    ~static_vector_non_trivial_storage() noexcept(is_nothrow_destructible_v<T>) { unsafe_destroy_all(); }

    /// \brief Direct access to the underlying storage.
    [[nodiscard]] auto data() const noexcept -> const_pointer { return reinterpret_cast<const_pointer>(_data); }

    /// \brief Direct access to the underlying storage.
    [[nodiscard]] auto data() noexcept -> pointer { return reinterpret_cast<pointer>(_data); }

    /// \brief Pointer to one-past-the-end.
    [[nodiscard]] auto end() const noexcept -> const_pointer { return data() + size(); }

    /// \brief Pointer to one-past-the-end.
    [[nodiscard]] auto end() noexcept -> pointer { return data() + size(); }

    /// \brief Number of elements in the storage.
    [[nodiscard]] auto size() const noexcept -> size_type { return _size; }

    /// \brief Maximum number of elements that can be allocated in the
    /// storage.
    [[nodiscard]] auto capacity() const noexcept -> size_type { return Capacity; }

    /// \brief Is the storage empty?
    [[nodiscard]] auto empty() const noexcept -> bool { return size() == size_type {0}; }

    /// \brief Is the storage full?
    [[nodiscard]] auto full() const noexcept -> bool { return size() == Capacity; }

    /// \brief Constructs an element in-place at the end of the embedded
    /// storage.
    template <typename... Args>
    auto emplace_back(Args&&... args) noexcept(noexcept(new(end()) T(forward<Args>(args)...))) -> void
    {
        TETL_ASSERT(!full());
        new (end()) T(forward<Args>(args)...);
        unsafe_set_size(static_cast<size_type>(size() + 1));
    }

    /// \brief Remove the last element from the container.
    auto pop_back() noexcept(is_nothrow_destructible_v<T>) -> void
    {
        TETL_ASSERT(!empty());
        auto* ptr = end() - 1;
        ptr->~T();
        unsafe_set_size(static_cast<size_type>(size() - 1));
    }

protected:
    /// \brief (unsafe) Changes the container size to new_size.
    ///
    /// \warning No elements are constructed or destroyed.
    auto unsafe_set_size(size_t newSize) noexcept -> void
    {
        TETL_ASSERT(newSize <= Capacity);
        _size = size_type(newSize);
    }

    /// \brief (unsafe) Destroy elements in the range [begin, end).
    ///
    /// \warning The size of the storage is not changed.
    template <typename InputIt>
    auto unsafe_destroy(InputIt first, InputIt last) noexcept(is_nothrow_destructible_v<T>) -> void
    {
        TETL_ASSERT(first >= data() && first <= end());
        TETL_ASSERT(last >= data() && last <= end());
        for (; first != last; ++first) { first->~T(); }
    }

    /// \brief (unsafe) Destroys all elements of the storage.
    ///
    /// \warning The size of the storage is not changed.
    auto unsafe_destroy_all() noexcept(is_nothrow_destructible_v<T>) -> void { unsafe_destroy(data(), end()); }

private:
    using raw_type     = remove_const_t<T>;
    using aligned      = aligned_storage_t<sizeof(raw_type), alignof(raw_type)>;
    using storage_type = conditional_t<!is_const_v<T>, aligned, aligned const>;

    alignas(alignof(T)) storage_type _data[Capacity];
    size_type _size = 0;
};

/// \brief Selects the vector storage.
template <typename T, size_t Capacity>
using static_vector_storage_type = conditional_t<Capacity == 0, static_vector_zero_storage<T>,
    conditional_t<is_trivial_v<T>, static_vector_trivial_storage<T, Capacity>,
        static_vector_non_trivial_storage<T, Capacity>>>;

} // namespace detail

/// \brief Dynamically-resizable fixed-capacity vector.
/// \include vector.cpp
template <typename T, size_t Capacity>
struct static_vector : detail::static_vector_storage_type<T, Capacity> {
private:
    static_assert(is_nothrow_destructible_v<T>);
    using base_type = detail::static_vector_storage_type<T, Capacity>;
    using self      = static_vector<T, Capacity>;

    using base_type::unsafe_destroy;
    using base_type::unsafe_destroy_all;
    using base_type::unsafe_set_size;

public:
    /// The type being used
    using value_type = typename base_type::value_type;
    /// The type being used
    using difference_type = ptrdiff_t;
    /// The type being used
    using reference = value_type&;
    /// The type being used
    using const_reference = value_type const&;
    /// The type being used
    using pointer = typename base_type::pointer;
    /// The type being used
    using const_pointer = typename base_type::const_pointer;
    /// The type being used
    using iterator = typename base_type::pointer;
    /// The type being used
    using const_iterator = typename base_type::const_pointer;
    /// The type being used
    using size_type = size_t;
    /// The type being used
    using reverse_iterator = etl::reverse_iterator<iterator>;
    /// The type being used
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

private:
    constexpr auto emplace_n(size_type n) noexcept(
        (is_move_constructible_v<T> && is_nothrow_move_constructible_v<T>)
        || (is_copy_constructible_v<T> && is_nothrow_copy_constructible_v<T>)) -> void
    {
        TETL_ASSERT(n <= capacity());
        while (n != size()) { emplace_back(T {}); }
    }

public:
    [[nodiscard]] constexpr auto begin() noexcept -> iterator { return data(); }
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator { return data(); }
    [[nodiscard]] constexpr auto end() noexcept -> iterator { return data() + size(); }
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator { return data() + size(); }

    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator { return reverse_iterator(end()); }
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }
    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator { return reverse_iterator(begin()); }
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    [[nodiscard]] constexpr auto cbegin() noexcept -> const_iterator { return begin(); }
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator { return begin(); }
    [[nodiscard]] constexpr auto cend() noexcept -> const_iterator { return end(); }
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    using base_type::emplace_back;

    using base_type::pop_back;

    /// \brief Appends value at the end of the vector.
    template <typename U>
        requires(is_constructible_v<T, U> && is_assignable_v<reference, U &&>)
    constexpr auto push_back(U&& value) noexcept(noexcept(emplace_back(forward<U>(value)))) -> void
    {
        TETL_ASSERT(!full());
        emplace_back(forward<U>(value));
    }

    template <typename InIt>
        requires(detail::InputIterator<InIt>)
    constexpr auto move_insert(const_iterator position, InIt first, InIt last) noexcept(
        noexcept(emplace_back(move(*first)))) -> iterator
    {
        assert_iterator_in_range(position);
        assert_valid_iterator_pair(first, last);
        if constexpr (detail::RandomAccessIterator<InIt>) {
            TETL_ASSERT(size() + static_cast<size_type>(last - first) <= capacity());
        }
        iterator b = end();

        // we insert at the end and then just rotate:
        for (; first != last; ++first) { emplace_back(move(*first)); }
        auto* writablePosition = begin() + (position - begin());
        rotate<iterator>(writablePosition, b, end());
        return writablePosition;
    }

    template <typename... Args>
        requires(is_constructible_v<T, Args...>)
    constexpr auto emplace(const_iterator position, Args&&... args) noexcept(
        noexcept(move_insert(position, declval<value_type*>(), declval<value_type*>()))) -> iterator
    {
        TETL_ASSERT(!full());
        assert_iterator_in_range(position);
        value_type a(forward<Args>(args)...);
        return move_insert(position, &a, &a + 1);
    }

    /// \brief Data access
    using base_type::data;

    constexpr auto insert(const_iterator position, value_type&& x) noexcept(noexcept(move_insert(position, &x, &x + 1)))
        -> iterator
        requires(is_move_constructible_v<T>)
    {
        TETL_ASSERT(!full());
        assert_iterator_in_range(position);
        return move_insert(position, &x, &x + 1);
    }

    constexpr auto insert(const_iterator position, size_type n, T const& x) noexcept(noexcept(push_back(x))) -> iterator
        requires(is_copy_constructible_v<T>)
    {
        assert_iterator_in_range(position);
        TETL_ASSERT(size() + n <= capacity());
        auto* b = end();
        while (n != 0) {
            push_back(x);
            --n;
        }

        auto* writablePosition = begin() + (position - begin());
        rotate(writablePosition, b, end());
        return writablePosition;
    }

    constexpr auto insert(const_iterator position, const_reference x) noexcept(
        noexcept(insert(position, size_type(1), x))) -> iterator
        requires(is_copy_constructible_v<T>)
    {
        TETL_ASSERT(!full());
        assert_iterator_in_range(position);
        return insert(position, size_type(1), x);
    }

    template <typename InputIt>
    constexpr auto insert(const_iterator position, InputIt first, InputIt last) noexcept(noexcept(emplace_back(*first)))
        -> iterator
        requires(
            detail::InputIterator<InputIt> && is_constructible_v<value_type, detail::iterator_reference_t<InputIt>>)
    {
        assert_iterator_in_range(position);
        assert_valid_iterator_pair(first, last);
        if constexpr (detail::RandomAccessIterator<InputIt>) {
            TETL_ASSERT(size() + static_cast<size_type>(last - first) <= capacity());
        }
        auto* b = end();

        // insert at the end and then just rotate:
        for (; first != last; ++first) { emplace_back(*first); }

        auto* writablePosition = begin() + (position - begin());
        rotate(writablePosition, b, end());
        return writablePosition;
    }

    /// \brief Clears the vector.
    constexpr void clear() noexcept
    {
        unsafe_destroy_all();
        unsafe_set_size(0);
    }

    constexpr static_vector() = default;

    template <etl::same_as<empty_c_array> Source = empty_c_array>
    constexpr static_vector(Source /*unused*/) noexcept
    {
    }

    template <etl::size_t Size>
        requires(Size <= Capacity)
    constexpr static_vector(c_array<T, Size>&& source)
    {
        move_insert(begin(), etl::begin(source), etl::end(source));
    }

    /// \brief Copy constructor.
    constexpr static_vector(static_vector const& other) noexcept(noexcept(insert(begin(), other.begin(), other.end())))
    {
        // Nothing to assert: size of other cannot exceed capacity because both
        // vectors have the same type
        insert(begin(), other.begin(), other.end());
    }

    /// \brief Move constructor.
    constexpr static_vector(static_vector&& other) noexcept(noexcept(move_insert(begin(), other.begin(), other.end())))
    {
        // Nothing to assert: size of other cannot exceed capacity because both
        // vectors have the same type
        move_insert(begin(), other.begin(), other.end());
    }

    /// \brief Copy assignment.
    constexpr auto operator=(static_vector const& other) noexcept(
        noexcept(clear()) && noexcept(insert(begin(), other.begin(), other.end())))
        -> static_vector& requires(is_assignable_v<reference, const_reference>) {
            // Nothing to assert: size of other cannot exceed capacity because both
            // vectors have the same type
            clear();
            insert(begin(), other.begin(), other.end());
            return *this;
        }

    /// \brief Move assignment.
    constexpr auto
    operator=(static_vector&& other) noexcept(
        noexcept(clear()) and noexcept(move_insert(begin(), other.begin(), other.end())))
        -> static_vector& requires(is_assignable_v<reference, reference>) {
            // Nothing to assert: size of other cannot exceed capacity because both
            // vectors have the same type
            clear();
            move_insert(begin(), other.begin(), other.end());
            return *this;
        }

    /// \brief Initializes vector with n default-constructed elements.
    explicit constexpr static_vector(size_type n) noexcept(noexcept(emplace_n(n)))
        requires(is_copy_constructible_v<T> || is_move_constructible_v<T>)
    {
        TETL_ASSERT(n <= capacity());
        emplace_n(n);
    }

    /// \brief Initializes vector with n with value.
    constexpr static_vector(size_type n, T const& value) noexcept(noexcept(insert(begin(), n, value)))
        requires(is_copy_constructible_v<T>)
    {
        TETL_ASSERT(n <= capacity());
        insert(begin(), n, value);
    }

    /// \brief Initialize vector from range [first, last).
    template <typename InputIter>
        requires(detail::InputIterator<InputIter>)
    constexpr static_vector(InputIter first, InputIter last)
    {
        if constexpr (detail::RandomAccessIterator<InputIter>) {
            TETL_ASSERT(last - first >= 0);
            TETL_ASSERT(static_cast<size_type>(last - first) <= capacity());
        }
        insert(begin(), first, last);
    }

    /// \brief Is the storage empty/full?
    using base_type::empty;

    using base_type::full;

    /// \brief Number of elements in the vector
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return base_type::size(); }

    /// \brief Maximum number of elements that can be allocated in the vector
    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type { return base_type::capacity(); }

    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type { return capacity(); }

    /// \brief assign
    template <typename InputIter>
        requires(detail::InputIterator<InputIter>)
    constexpr auto assign(InputIter first, InputIter last) noexcept(
        noexcept(clear()) and noexcept(insert(begin(), first, last))) -> void
    {
        if constexpr (detail::RandomAccessIterator<InputIter>) {
            TETL_ASSERT(last - first >= 0);
            TETL_ASSERT(static_cast<size_type>(last - first) <= capacity());
        }
        clear();
        insert(begin(), first, last);
    }

    constexpr auto assign(size_type n, T const& u) -> void
        requires(is_copy_constructible_v<T>)
    {
        TETL_ASSERT(n <= capacity());
        clear();
        insert(begin(), n, u);
    }

    /// \brief Unchecked access to element at index pos (UB if index not in
    [[nodiscard]] constexpr auto operator[](size_type pos) noexcept -> reference { return detail::index(*this, pos); }

    /// \brief Unchecked access to element at index pos (UB if index not in
    [[nodiscard]] constexpr auto operator[](size_type pos) const noexcept -> const_reference
    {
        return detail::index(*this, pos);
    }

    /// \brief front
    [[nodiscard]] constexpr auto front() noexcept -> reference { return detail::index(*this, 0); }

    [[nodiscard]] constexpr auto front() const noexcept -> const_reference { return detail::index(*this, 0); }

    /// \brief back
    [[nodiscard]] constexpr auto back() noexcept -> reference
    {
        TETL_ASSERT(!empty());
        return detail::index(*this, static_cast<size_type>(size() - 1));
    }

    [[nodiscard]] constexpr auto back() const noexcept -> const_reference
    {
        TETL_ASSERT(!empty());
        return detail::index(*this, static_cast<size_type>(size() - 1));
    }

    /// \brief erase
    constexpr auto erase(const_iterator position) noexcept -> iterator
        requires(detail::is_movable_v<value_type>)
    {
        assert_iterator_in_range(position);
        return erase(position, position + 1);
    }

    constexpr auto erase(const_iterator first, const_iterator last) noexcept -> iterator
        requires(detail::is_movable_v<value_type>)
    {
        assert_iterator_pair_in_range(first, last);
        iterator p = begin() + (first - begin());
        if (first != last) {
            unsafe_destroy(move(p + (last - first), end(), p), end());
            unsafe_set_size(size() - static_cast<size_type>(last - first));
        }

        return p;
    }

    /// \brief Exchanges the contents of the container with those of other.
    constexpr auto swap(static_vector& other) noexcept(is_nothrow_swappable_v<T>) -> void
        requires(is_assignable_v<T&, T &&>)
    {
        using etl::move;

        static_vector tmp = move(other);
        other             = move(*this);
        (*this)           = move(tmp);
    }

    /// \brief Resizes the container to contain sz elements. If elements need to
    /// be appended, these are move-constructed from `T{}` (or copy-constructed
    constexpr auto resize(size_type sz) noexcept((is_move_constructible_v<T> && is_nothrow_move_constructible_v<T>)
                                                 || (is_copy_constructible_v<T> && is_nothrow_copy_constructible_v<T>))
        -> void
        requires(detail::is_movable_v<value_type>)
    {
        if (sz == size()) { return; }

        if (sz > size()) {
            emplace_n(sz);
            return;
        }

        erase(end() - (size() - sz), end());
    }

    constexpr auto resize(size_type sz, T const& value) noexcept(is_nothrow_copy_constructible_v<T>) -> void
        requires(is_copy_constructible_v<T>)
    {
        if (sz == size()) { return; }
        if (sz > size()) {
            TETL_ASSERT(sz <= capacity());
            insert(end(), sz - size(), value);
        } else {
            erase(end() - (size() - sz), end());
        }
    }

private:
    template <typename It>
    constexpr void assert_iterator_in_range([[maybe_unused]] It it) noexcept
    {
        static_assert(is_pointer_v<It>);
        TETL_ASSERT(begin() <= it);
        TETL_ASSERT(it <= end());
    }

    template <typename It0, typename It1>
    constexpr void assert_valid_iterator_pair([[maybe_unused]] It0 first, [[maybe_unused]] It1 last) noexcept
    {
        static_assert(is_pointer_v<It0>);
        static_assert(is_pointer_v<It1>);
        TETL_ASSERT(first <= last);
    }

    template <typename It0, typename It1>
    constexpr void assert_iterator_pair_in_range([[maybe_unused]] It0 first, [[maybe_unused]] It1 last) noexcept
    {
        assert_iterator_in_range(first);
        assert_iterator_in_range(last);
        assert_valid_iterator_pair(first, last);
    }
};

/// \brief Specializes the swap algorithm for static_vector. Swaps the
/// contents of lhs and rhs.
template <typename T, size_t Capacity>
constexpr auto swap(static_vector<T, Capacity>& lhs, static_vector<T, Capacity>& rhs) noexcept -> void
{
    lhs.swap(rhs);
}

/// \brief Compares the contents of two vectors.
///
/// \details Checks if the contents of lhs and rhs are equal, that is, they have
/// the same number of elements and each element in lhs compares equal with the
/// element in rhs at the same position.
template <typename T, size_t Capacity>
constexpr auto operator==(static_vector<T, Capacity> const& lhs, static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    if (size(lhs) == size(rhs)) { return equal(begin(lhs), end(lhs), begin(rhs), end(rhs), equal_to<> {}); }

    return false;
}

template <typename T, size_t Capacity>
constexpr auto operator!=(static_vector<T, Capacity> const& lhs, static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return !(lhs == rhs);
}

/// \brief Compares the contents of two vectors.
///
/// \details Compares the contents of lhs and rhs lexicographically. The
/// comparison is performed by a function equivalent to
/// lexicographical_compare.
template <typename T, size_t Capacity>
constexpr auto operator<(static_vector<T, Capacity> const& lhs, static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return lexicographical_compare(begin(lhs), end(lhs), begin(rhs), end(rhs));
}

template <typename T, size_t Capacity>
constexpr auto operator<=(static_vector<T, Capacity> const& lhs, static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return !(rhs < lhs);
}

template <typename T, size_t Capacity>
constexpr auto operator>(static_vector<T, Capacity> const& lhs, static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return rhs < lhs;
}

template <typename T, size_t Capacity>
constexpr auto operator>=(static_vector<T, Capacity> const& lhs, static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return !(lhs < rhs);
}

/// \brief Erases all elements that satisfy the predicate pred from the
/// container.
/// \returns The number of erased elements.
///
/// https://en.cppreference.com/w/cpp/container/vector/erase2
template <typename T, size_t Capacity, typename Predicate>
constexpr auto erase_if(static_vector<T, Capacity>& c, Predicate pred) -> typename static_vector<T, Capacity>::size_type
{
    auto* it = remove_if(c.begin(), c.end(), pred);
    auto r   = distance(it, c.end());
    c.erase(it, c.end());
    return static_cast<typename static_vector<T, Capacity>::size_type>(r);
}

template <typename T, size_t Capacity, typename U>
constexpr auto erase(static_vector<T, Capacity>& c, U const& value) -> typename static_vector<T, Capacity>::size_type
{
    return erase_if(c, [&value](auto const& item) { return item == value; });
}

} // namespace etl

#endif // TETL_VECTOR_STATIC_VECTOR_HPP

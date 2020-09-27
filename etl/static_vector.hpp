/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_STATIC_VECTOR_HPP
#define TAETL_STATIC_VECTOR_HPP

#include "etl/algorithm.hpp"
#include "etl/array.hpp"
#include "etl/cassert.hpp"
#include "etl/definitions.hpp"
#include "etl/functional.hpp"
#include "etl/iterator.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

namespace etl
{
namespace detail
{
template <typename T>
inline constexpr bool is_movable_v = etl::is_object_v<T>&& etl::is_assignable_v<T&, T>&&
    etl::is_move_constructible_v<T>&& etl::is_swappable_v<T&>;

template <typename Rng>
using range_iterator_t = decltype(etl::begin(etl::declval<Rng>()));

template <typename T>
using iterator_reference_t = typename etl::iterator_traits<T>::reference;

template <typename T>
using iterator_category_t = typename etl::iterator_traits<T>::iterator_category;

template <typename T, typename Cat, typename = void>
struct Iterator_ : etl::false_type
{
};

template <typename T, typename Cat>
struct Iterator_<T, Cat, etl::void_t<iterator_category_t<T>>>
    : etl::bool_constant<etl::is_convertible_v<iterator_category_t<T>, Cat>>
{
};

// Concepts (poor-man emulation using type traits)
template <typename T>
static constexpr bool InputIterator = Iterator_<T, etl::input_iterator_tag> {};

template <typename T>
static constexpr bool ForwardIterator = Iterator_<T, etl::forward_iterator_tag> {};

template <typename T>
static constexpr bool OutputIterator
    = Iterator_<T, etl::output_iterator_tag> {} || ForwardIterator<T>;

template <typename T>
static constexpr bool BidirectionalIterator
    = Iterator_<T, etl::bidirectional_iterator_tag> {};

template <typename T>
static constexpr bool RandomAccessIterator
    = Iterator_<T, etl::random_access_iterator_tag> {};

template <typename T>
static constexpr bool RandomAccessRange = RandomAccessIterator<range_iterator_t<T>>;

/**
 * @brief Smallest fixed-width unsigned integer type that can represent values in the
 * range [0, N].
 */
// clang-format off
template<size_t N>
using smallest_size_t =
            etl::conditional_t<(N < etl::numeric_limits<uint8_t>::max()),  uint8_t,
            etl::conditional_t<(N < etl::numeric_limits<uint16_t>::max()), uint16_t,
            etl::conditional_t<(N < etl::numeric_limits<uint32_t>::max()), uint32_t,
            etl::conditional_t<(N < etl::numeric_limits<uint64_t>::max()), uint64_t,
                                                                 size_t>>>>;
// clang-format on

/**
 * @brief Index a range doing bound checks in debug builds
 * FCV_REQUIRES_(RandomAccessRange<Rng>)
 */
template <typename Rng, typename Index>
constexpr decltype(auto) index(Rng&& rng, Index&& i) noexcept
{
    ETL_ASSERT(static_cast<ptrdiff_t>(i) < (etl::end(rng) - etl::begin(rng)));
    return etl::begin(etl::forward<Rng>(rng))[etl::forward<Index>(i)];
}

/**
 * @brief Storage for zero elements.
 */
template <typename T>
class sv_zero_storage
{
public:
    using size_type       = uint8_t;
    using value_type      = T;
    using difference_type = ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;

    /**
     * @brief Defaulted constructor.
     */
    constexpr sv_zero_storage() = default;

    /**
     * @brief Defaulted copy constructor.
     */
    constexpr sv_zero_storage(sv_zero_storage const&) = default;

    /**
     * @brief Defaulted copy assignment .
     */
    constexpr auto operator =(sv_zero_storage const&) noexcept
        -> sv_zero_storage& = default;

    /**
     * @brief Defaulted move constructor.
     */
    constexpr sv_zero_storage(sv_zero_storage&&) noexcept = default;

    /**
     * @brief Defaulted move assignment.
     */
    constexpr auto operator=(sv_zero_storage&&) noexcept -> sv_zero_storage& = default;

    /**
     * @brief Defaulted destructor.
     */
    ~sv_zero_storage() = default;

    /**
     * @brief Pointer to the data in the storage.
     */
    [[nodiscard]] static constexpr auto data() noexcept -> pointer { return nullptr; }

    /**
     * @brief Number of elements currently stored.
     */
    [[nodiscard]] static constexpr auto size() noexcept -> size_type { return 0; }

    /**
     * @brief Capacity of the storage.
     */
    [[nodiscard]] static constexpr auto capacity() noexcept -> size_type { return 0; }

    /**
     * @brief Is the storage empty?
     */
    [[nodiscard]] static constexpr auto empty() noexcept -> bool { return true; }

    /**
     * @brief Is the storage full?
     */
    [[nodiscard]] static constexpr auto full() noexcept -> bool { return true; }

    /**
     * @brief Constructs a new element at the end of the storagein-place. Increases size
     * of the storage by one. Always fails for empty storage.
     */
    template <typename... Args>
    static constexpr auto emplace_back(Args&&...) noexcept
        -> etl::enable_if_t<etl::is_constructible_v<T, Args...>, void>
    {
        ETL_ASSERT(false && "tried to emplace_back on empty storage");
    }

    /**
     * @brief Removes the last element of the storage. Always fails for empty storage.
     */
    static constexpr void pop_back() noexcept
    {
        ETL_ASSERT(false && "tried to pop_back on empty storage");
    }

protected:
    /**
     * @brief Changes the size of the storage without adding or removing elements
     * (unsafe). The size of an empty storage can only be changed to 0.
     */
    static constexpr void unsafe_set_size([[maybe_unused]] size_t new_size) noexcept
    {
        ETL_ASSERT(new_size == 0
                   && "tried to change size of empty storage to "
                      "non-zero value");
    }

    /**
     * @brief Destroys all elements of the storage in range [begin, end) without changings
     * its size (unsafe). Nothing to destroy since the storage is empty.
     */
    template <typename InputIt>
    static constexpr auto unsafe_destroy(InputIt /* begin */, InputIt /* end */) noexcept
        -> void
    {
    }

    /**
     * @brief Destroys all elements of the storage without changing its size (unsafe).
     * Nothing to destroy since the storage is empty.
     */
    static constexpr void unsafe_destroy_all() noexcept { }
};

/**
 * @brief Storage for trivial types.
 */
template <typename T, size_t Capacity>
class sv_trivial_storage
{
    static_assert(etl::is_trivial_v<T>,
                  "storage::trivial<T, C> requires etl::is_trivial_v<T>");
    static_assert(Capacity != size_t {0}, "Capacity must be greater "
                                          "than zero (use "
                                          "storage::sv_zero_storage instead)");

public:
    using size_type       = smallest_size_t<Capacity>;
    using value_type      = T;
    using difference_type = ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;

    constexpr sv_trivial_storage() noexcept = default;

    constexpr sv_trivial_storage(sv_trivial_storage const&) noexcept = default;
    constexpr auto operator    =(sv_trivial_storage const&) noexcept
        -> sv_trivial_storage& = default;

    constexpr sv_trivial_storage(sv_trivial_storage&&) noexcept = default;
    constexpr auto operator    =(sv_trivial_storage&&) noexcept
        -> sv_trivial_storage& = default;

    ~sv_trivial_storage() = default;

    /**
     * @brief Direct access to the underlying storage.
     */
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
    {
        return data_.data();
    }

    /**
     * @brief Direct access to the underlying storage.
     */
    [[nodiscard]] constexpr auto data() noexcept -> pointer { return data_.data(); }

    /**
     * @brief Number of elements in the storage.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return size_; }

    /**
     * @brief Maximum number of elements that can be allocated in the storage.
     */
    [[nodiscard]] constexpr auto capacity() noexcept -> size_type { return Capacity; }

    /**
     * @brief Is the storage empty?
     */
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size() == size_type {0};
    }

    /**
     * @brief Is the storage full?
     */
    [[nodiscard]] constexpr auto full() const noexcept -> bool
    {
        return size() == Capacity;
    }

    /**
     * @brief Constructs an element in-place at the end of the storage.
     */
    template <typename... Args>
    constexpr auto emplace_back(Args&&... args) noexcept -> etl::enable_if_t<
        etl::is_constructible_v<T, Args...> and etl::is_assignable_v<value_type&, T>,
        void>
    {
        ETL_ASSERT(!full() && "tried to emplace_back on full storage!");
        index(data_, size()) = T(etl::forward<Args>(args)...);
        unsafe_set_size(static_cast<size_type>(size() + 1));
    }

    /**
     * @brief Remove the last element from the container.
     */
    constexpr auto pop_back() noexcept -> void
    {
        ETL_ASSERT(!empty() && "tried to pop_back from empty storage!");
        unsafe_set_size(static_cast<size_type>(size() - 1));
    }

protected:
    /**
     * @brief (unsafe) Changes the container size to \p new_size.
     *
     * @warning No elements are constructed or destroyed.
     */
    constexpr auto unsafe_set_size(size_t new_size) noexcept -> void
    {
        ETL_ASSERT(new_size <= Capacity && "new_size out-of-bounds [0, Capacity]");
        size_ = size_type(new_size);
    }

    /**
     * @brief (unsafe) Destroy elements in the range [begin, end).
     *
     * @warning The size of the storage is not changed.
     */
    template <typename InputIt>
    constexpr auto unsafe_destroy(InputIt, InputIt) noexcept -> void
    {
    }

    /**
     * @brief (unsafe) Destroys all elements of the storage.
     *
     * @warning The size of the storage is not changed.
     */
    constexpr auto unsafe_destroy_all() noexcept -> void { }

private:
    // If the value_type is const, make a const array of
    // non-const elements:
    using data_t = etl::conditional_t<!etl::is_const_v<T>, etl::array<T, Capacity>,
                                      const etl::array<etl::remove_const_t<T>, Capacity>>;
    alignas(alignof(T)) data_t data_ {};

    size_type size_ = 0;
};

/**
 * @brief Storage for non-trivial elements.
 */
template <typename T, size_t Capacity>
class sv_non_trivial_storage
{
    static_assert(!etl::is_trivial_v<T>,
                  "use storage::trivial for etl::is_trivial_v<T> elements");
    static_assert(Capacity != size_t {0}, "Capacity must be greater than zero!");

public:
    using size_type       = smallest_size_t<Capacity>;
    using value_type      = T;
    using difference_type = ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;

    constexpr sv_non_trivial_storage() = default;

    constexpr sv_non_trivial_storage(sv_non_trivial_storage const&) = default;
    constexpr auto operator        =(sv_non_trivial_storage const&)
        -> sv_non_trivial_storage& = default;

    constexpr sv_non_trivial_storage(sv_non_trivial_storage&&) = default;
    constexpr auto operator                                    =(sv_non_trivial_storage&&)
        -> sv_non_trivial_storage&                             = default;

    ~sv_non_trivial_storage() noexcept(etl::is_nothrow_destructible_v<T>)
    {
        unsafe_destroy_all();
    }

    /**
     * @brief Direct access to the underlying storage.
     */
    [[nodiscard]] auto data() const noexcept -> const_pointer
    {
        return reinterpret_cast<const_pointer>(data_);
    }

    /**
     * @brief Direct access to the underlying storage.
     */
    [[nodiscard]] auto data() noexcept -> pointer
    {
        return reinterpret_cast<pointer>(data_);
    }

    /**
     * @brief Pointer to one-past-the-end.
     */
    [[nodiscard]] auto end() const noexcept -> const_pointer { return data() + size(); }

    /**
     * @brief Pointer to one-past-the-end.
     */
    [[nodiscard]] auto end() noexcept -> pointer { return data() + size(); }

    /**
     * @brief Number of elements in the storage.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return size_; }

    /**
     * @brief Maximum number of elements that can be allocated in the storage.
     */
    [[nodiscard]] constexpr auto capacity() noexcept -> size_type { return Capacity; }

    /**
     * @brief Is the storage empty?
     */
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size() == size_type {0};
    }

    /**
     * @brief Is the storage full?
     */
    [[nodiscard]] constexpr auto full() const noexcept -> bool
    {
        return size() == Capacity;
    }

    /**
     * @brief Constructs an element in-place at the end of the embedded storage.
     */
    template <typename... Args>
    auto emplace_back(Args&&... args) noexcept(
        noexcept(new (end()) T(etl::forward<Args>(args)...)))
        -> etl::enable_if_t<etl::is_copy_constructible_v<T>, void>
    {
        ETL_ASSERT(!full() && "tried to emplace_back on full storage");
        new (end()) T(etl::forward<Args>(args)...);
        unsafe_set_size(static_cast<size_type>(size() + 1));
    }

    /**
     * @brief Remove the last element from the container.
     */
    auto pop_back() noexcept(etl::is_nothrow_destructible_v<T>) -> void
    {
        ETL_ASSERT(!empty() && "tried to pop_back from empty storage!");
        auto ptr = end() - 1;
        ptr->~T();
        unsafe_set_size(static_cast<size_type>(size() - 1));
    }

protected:
    /**
     * @brief (unsafe) Changes the container size to \p new_size.
     *
     * @warning No elements are constructed or destroyed.
     */
    constexpr void unsafe_set_size(size_t new_size) noexcept
    {
        ETL_ASSERT(new_size <= Capacity && "new_size out-of-bounds [0, Capacity)");
        size_ = size_type(new_size);
    }

    /**
     * @brief (unsafe) Destroy elements in the range [begin, end).
     *
     * @warning The size of the storage is not changed.
     */
    template <typename InputIt>
    void unsafe_destroy(InputIt first,
                        InputIt last) noexcept(etl::is_nothrow_destructible_v<T>)
    {
        ETL_ASSERT(first >= data() && first <= end() && "first is out-of-bounds");
        ETL_ASSERT(last >= data() && last <= end() && "last is out-of-bounds");
        for (; first != last; ++first) { first->~T(); }
    }

    /**
     * @brief (unsafe) Destroys all elements of the storage.
     *
     * @warning The size of the storage is not changed.
     */
    void unsafe_destroy_all() noexcept(etl::is_nothrow_destructible_v<T>)
    {
        unsafe_destroy(data(), end());
    }

private:
    using raw_type          = etl::remove_const_t<T>;
    using aligned_storage_t = etl::aligned_storage_t<sizeof(raw_type), alignof(raw_type)>;
    using storage_type      = etl::conditional_t<!etl::is_const_v<T>, aligned_storage_t,
                                            const aligned_storage_t>;

    alignas(alignof(T)) storage_type data_[Capacity];
    size_type size_ = 0;
};

/**
 * @brief Selects the vector storage.
 */
template <typename T, size_t Capacity>
using storage_type = etl::conditional_t<
    Capacity == 0, sv_zero_storage<T>,
    etl::conditional_t<etl::is_trivial_v<T>, sv_trivial_storage<T, Capacity>,
                       sv_non_trivial_storage<T, Capacity>>>;

}  // namespace detail

/**
 * @brief Dynamically-resizable fixed-capacity vector.
 */
template <typename T, size_t Capacity>
class static_vector : private detail::storage_type<T, Capacity>
{
private:
    static_assert(etl::is_nothrow_destructible_v<T>, "T must be nothrow destructible");
    using base_type = detail::storage_type<T, Capacity>;
    using self      = static_vector<T, Capacity>;

    using base_type::unsafe_destroy;
    using base_type::unsafe_destroy_all;
    using base_type::unsafe_set_size;

public:
    using value_type      = typename base_type::value_type;
    using difference_type = ptrdiff_t;
    using reference       = value_type&;
    using const_reference = value_type const&;
    using pointer         = typename base_type::pointer;
    using const_pointer   = typename base_type::const_pointer;
    using iterator        = typename base_type::pointer;
    using const_iterator  = typename base_type::const_pointer;
    using size_type       = size_t;

    // using reverse_iterator       = ::etl::reverse_iterator<iterator>;
    // using const_reverse_iterator = ::etl::reverse_iterator<const_iterator>;
private:
    constexpr auto emplace_n(size_type n) noexcept(
        (etl::is_move_constructible_v<T> && etl::is_nothrow_move_constructible_v<T>)
        || (etl::is_copy_constructible_v<T> && etl::is_nothrow_copy_constructible_v<T>))
        -> etl::enable_if_t<
            etl::is_move_constructible_v<T> or etl::is_copy_constructible_v<T>, void>
    {
        ETL_ASSERT(n <= capacity()
                   && "static_vector cannot be "
                      "resized to a size greater than "
                      "capacity");
        while (n != size()) { emplace_back(T {}); }
    }

public:
    [[nodiscard]] constexpr auto begin() noexcept -> iterator { return data(); }
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return data();
    }
    [[nodiscard]] constexpr auto end() noexcept -> iterator { return data() + size(); }
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return data() + size();
    }

    // [[nodiscard]] auto rbegin() noexcept -> reverse_iterator
    // {
    //     return reverse_iterator(end());
    // }
    // [[nodiscard]] auto rbegin() const noexcept -> const_reverse_iterator
    // {
    //     return const_reverse_iterator(end());
    // }
    // [[nodiscard]] auto rend() noexcept -> reverse_iterator
    // {
    //     return reverse_iterator(this->begin());
    // }
    // [[nodiscard]] auto rend() const noexcept -> const_reverse_iterator
    // {
    //     return const_reverse_iterator(this->begin());
    // }

    [[nodiscard]] constexpr auto cbegin() noexcept -> const_iterator { return begin(); }
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return begin();
    }
    [[nodiscard]] constexpr auto cend() noexcept -> const_iterator { return end(); }
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    /**
     * @brief
     */
    using base_type::emplace_back;

    /**
     * @brief
     */
    using base_type::pop_back;

    /**
     * @brief Appends \p value at the end of the vector.
     */
    template <typename U>
    constexpr auto
    push_back(U&& value) noexcept(noexcept(emplace_back(etl::forward<U>(value))))
        -> etl::enable_if_t<
            etl::is_constructible_v<T, U> && etl::is_assignable_v<reference, U&&>, void>
    {
        ETL_ASSERT(!full() && "vector is full!");
        emplace_back(etl::forward<U>(value));
    }

    /**
     * @brief FCV_REQUIRES_(detail::InputIterator<InputIt>)
     */
    template <class InputIt>
    constexpr iterator
    move_insert(const_iterator position, InputIt first,
                InputIt last) noexcept(noexcept(emplace_back(etl::move(*first))))
    {
        assert_iterator_in_range(position);
        assert_valid_iterator_pair(first, last);
        if constexpr (detail::RandomAccessIterator<InputIt>)
        {
            ETL_ASSERT(size() + static_cast<size_type>(last - first) <= capacity()
                       && "trying to insert beyond capacity!");
        }
        iterator b = end();

        // we insert at the end and then just rotate:
        for (; first != last; ++first) { emplace_back(etl::move(*first)); }
        auto writable_position = begin() + (position - begin());
        etl::rotate<iterator>(writable_position, b, end());
        return writable_position;
    }

    /**
     * @brief
     */
    template <typename... Args>
    constexpr auto emplace(const_iterator position, Args&&... args) noexcept(noexcept(
        move_insert(position, etl::declval<value_type*>(), etl::declval<value_type*>())))
        -> etl::enable_if_t<etl::is_constructible_v<T, Args...>, iterator>
    {
        ETL_ASSERT(!full() && "tried emplace on full static_vector!");
        assert_iterator_in_range(position);
        value_type a(etl::forward<Args>(args)...);
        return move_insert(position, &a, &a + 1);
    }

    /**
     * @brief Data access
     */
    using base_type::data;

    /**
     * @brief
     */
    constexpr auto
    insert(const_iterator position,
           value_type&& x) noexcept(noexcept(move_insert(position, &x, &x + 1)))
        -> etl::enable_if_t<etl::is_move_constructible_v<T>, iterator>
    {
        ETL_ASSERT(!full() && "tried insert on full static_vector!");
        assert_iterator_in_range(position);
        return move_insert(position, &x, &x + 1);
    }

    /**
     * @brief
     */
    constexpr auto insert(const_iterator position, size_type n,
                          const T& x) noexcept(noexcept(push_back(x)))
        -> etl::enable_if_t<etl::is_copy_constructible_v<T>, iterator>
    {
        assert_iterator_in_range(position);
        ETL_ASSERT(size() + n <= capacity() && "trying to insert beyond capacity!");
        auto b = end();
        while (n != 0)
        {
            push_back(x);
            --n;
        }

        auto writable_position = begin() + (position - begin());
        etl::rotate(writable_position, b, end());
        return writable_position;
    }

    /**
     * @brief
     */
    constexpr auto
    insert(const_iterator position,
           const_reference x) noexcept(noexcept(insert(position, size_type(1), x)))
        -> etl::enable_if_t<etl::is_copy_constructible_v<T>, iterator>
    {
        ETL_ASSERT(!full() && "tried insert on full static_vector!");
        assert_iterator_in_range(position);
        return insert(position, size_type(1), x);
    }

    /**
     * @brief detail::InputIterator<InputIt>and etl::is_constructible_v<value_type,
     * detail::iterator_reference_t<InputIt>>
     */
    template <class InputIt>
    constexpr iterator insert(const_iterator position, InputIt first,
                              InputIt last) noexcept(noexcept(emplace_back(*first)))
    {
        assert_iterator_in_range(position);
        assert_valid_iterator_pair(first, last);
        if constexpr (detail::RandomAccessIterator<InputIt>)
        {
            ETL_ASSERT(size() + static_cast<size_type>(last - first) <= capacity()
                       && "trying to insert beyond capacity!");
        }
        auto b = end();

        // insert at the end and then just rotate:
        for (; first != last; ++first) { emplace_back(*first); }

        auto writable_position = begin() + (position - begin());
        etl::rotate(writable_position, b, end());
        return writable_position;
    }

    /**
     * @brief Clears the vector.
     */
    constexpr void clear() noexcept
    {
        unsafe_destroy_all();
        unsafe_set_size(0);
    }

    /**
     * @brief Default constructor.
     */
    constexpr static_vector() = default;

    /**
     * @brief Copy constructor.
     */
    constexpr static_vector(static_vector const& other) noexcept(
        noexcept(insert(begin(), other.begin(), other.end())))
    {
        // Nothing to assert: size of other cannot exceed capacity because both vectors
        // have the same type
        insert(begin(), other.begin(), other.end());
    }

    /**
     * @brief Move constructor.
     */
    constexpr static_vector(static_vector&& other) noexcept(
        noexcept(move_insert(begin(), other.begin(), other.end())))
    {
        // Nothing to assert: size of other cannot exceed capacity because both vectors
        // have the same type
        move_insert(begin(), other.begin(), other.end());
    }

    /**
     * @brief Copy assignment.
     */
    constexpr auto operator=(static_vector const& other) noexcept(
        noexcept(clear()) && noexcept(insert(begin(), other.begin(), other.end())))
        -> etl::enable_if_t<etl::is_assignable_v<reference, const_reference>,
                            static_vector&>
    {
        // Nothing to assert: size of other cannot exceed capacity because both vectors
        // have the same type
        clear();
        insert(this->begin(), other.begin(), other.end());
        return *this;
    }

    /**
     * @brief Move assignment.
     */
    constexpr auto operator=(static_vector&& other) noexcept(
        noexcept(clear()) and noexcept(move_insert(begin(), other.begin(), other.end())))
        -> etl::enable_if_t<etl::is_assignable_v<reference, reference>, static_vector&>
    {
        // Nothing to assert: size of other cannot exceed capacity because both vectors
        // have the same type
        clear();
        move_insert(this->begin(), other.begin(), other.end());
        return *this;
    }

    /**
     * @brief Initializes vector with \p n default-constructed elements.
     *
     * @todo FCV_REQUIRES(etl::is_copy_constructible_v<T> ||
     * etl::is_move_constructible_v<T>)
     */
    explicit constexpr static_vector(size_type n) noexcept(noexcept(emplace_n(n)))
    {
        ETL_ASSERT(n <= capacity() && "size exceeds capacity");
        emplace_n(n);
    }

    /**
     * @brief Initializes vector with \p n with \p value.
     *
     * @todo FCV_REQUIRES(etl::is_copy_constructible_v<T>)
     */
    constexpr static_vector(size_type n,
                            T const& value) noexcept(noexcept(insert(begin(), n, value)))
    {
        ETL_ASSERT(n <= capacity() && "size exceeds capacity");
        this->insert(this->begin(), n, value);
    }

    /**
     * @brief Initialize vector from range [first, last).
     *
     * @todo FCV_REQUIRES_(detail::InputIterator<InputIt>)
     */
    template <typename InputIter>
    constexpr static_vector(InputIter first, InputIter last)
    {
        if constexpr (detail::RandomAccessIterator<InputIter>)
        {
            ETL_ASSERT(last - first >= 0);
            ETL_ASSERT(static_cast<size_type>(last - first) <= capacity()
                       && "range size exceeds capacity");
        }
        insert(this->begin(), first, last);
    }

    /**
     * @brief Is the storage empty?
     */
    using base_type::empty;

    /**
     * @brief Is the storage full?
     */
    using base_type::full;

    /**
     * @brief Number of elements in the vector
     */
    constexpr auto size() const noexcept -> size_type { return base_type::size(); }

    /**
     * @brief Maximum number of elements that can be allocated in the vector
     */
    constexpr auto capacity() noexcept -> size_type { return base_type::capacity(); }

    /**
     * @brief Maximum number of elements that can be allocated in the vector
     */
    constexpr auto max_size() noexcept -> size_type { return capacity(); }

    /**
     * @brief Resizes the container to contain \p sz elements. If elements need to be
     * appended, these are move-constructed from `T{}` (or copy-constructed if `T` is not
     * `etl::is_move_constructible_v`).
     */
    constexpr auto resize(size_type sz) noexcept(
        (etl::is_move_constructible_v<T> && etl::is_nothrow_move_constructible_v<T>)
        || (etl::is_copy_constructible_v<T> && etl::is_nothrow_copy_constructible_v<T>))
        -> etl::enable_if_t<detail::is_movable_v<value_type>, void>
    {
        if (sz == size()) { return; }

        if (sz > size())
        {
            emplace_n(sz);
            return;
        }

        erase(end() - (size() - sz), end());
    }

    /**
     * @brief
     */
    template <class InputIter>
    constexpr auto assign(InputIter first, InputIter last) noexcept(
        noexcept(clear()) and noexcept(insert(begin(), first, last)))
        -> etl::enable_if_t<detail::InputIterator<InputIter>, void>
    {
        if constexpr (detail::RandomAccessIterator<InputIter>)
        {
            ETL_ASSERT(last - first >= 0);
            ETL_ASSERT(static_cast<size_type>(last - first) <= capacity()
                       && "range size exceeds capacity");
        }
        clear();
        insert(this->begin(), first, last);
    }

    /**
     * @brief
     */
    constexpr auto assign(size_type n, const T& u)
        -> etl::enable_if_t<etl::is_copy_constructible_v<T>, void>
    {
        ETL_ASSERT(n <= capacity() && "size exceeds capacity");
        clear();
        insert(this->begin(), n, u);
    }

    /**
     * @brief Unchecked access to element at index \p pos (UB if index not in range)
     */
    [[nodiscard]] constexpr auto operator[](size_type pos) noexcept -> reference
    {
        return detail::index(*this, pos);
    }

    /**
     * @brief Unchecked access to element at index \p pos (UB if index not in range)
     */
    [[nodiscard]] constexpr auto operator[](size_type pos) const noexcept
        -> const_reference
    {
        return detail::index(*this, pos);
    }

    /**
     * @brief
     */
    [[nodiscard]] constexpr auto front() noexcept -> reference
    {
        return detail::index(*this, 0);
    }

    /**
     * @brief
     */
    [[nodiscard]] constexpr auto front() const noexcept -> const_reference
    {
        return detail::index(*this, 0);
    }

    /**
     * @brief
     */
    [[nodiscard]] constexpr auto back() noexcept -> reference
    {
        ETL_ASSERT(!empty() && "calling back on an empty vector");
        return detail::index(*this, static_cast<size_type>(size() - 1));
    }

    /**
     * @brief
     */
    [[nodiscard]] constexpr auto back() const noexcept -> const_reference
    {
        ETL_ASSERT(!empty() && "calling back on an empty vector");
        return detail::index(*this, static_cast<size_type>(size() - 1));
    }

    /**
     * @brief
     */
    constexpr auto erase(const_iterator position) noexcept
        -> etl::enable_if_t<detail::is_movable_v<value_type>, iterator>
    {
        assert_iterator_in_range(position);
        return erase(position, position + 1);
    }

    /**
     * @brief
     */
    constexpr auto erase(const_iterator first, const_iterator last) noexcept
        -> etl::enable_if_t<detail::is_movable_v<value_type>, iterator>
    {
        assert_iterator_pair_in_range(first, last);
        iterator p = begin() + (first - begin());
        if (first != last)
        {
            unsafe_destroy(etl::move(p + (last - first), end(), p), end());
            unsafe_set_size(size() - static_cast<size_type>(last - first));
        }

        return p;
    }

    /**
     * @brief
     */
    constexpr auto swap(static_vector& other) noexcept(etl::is_nothrow_swappable_v<T>)
        -> etl::enable_if_t<etl::is_assignable_v<T&, T&&>, void>
    {
        static_vector tmp = etl::move(other);
        other             = etl::move(*this);
        (*this)           = etl::move(tmp);
    }

    /**
     * @brief Resizes the container to contain \p sz elements. If elements need to be
     * appended, these are copy-constructed from \p value.
     */
    constexpr auto
    resize(size_type sz, T const& value) noexcept(etl::is_nothrow_copy_constructible_v<T>)
        -> etl::enable_if_t<etl::is_copy_constructible_v<T>, void>
    {
        if (sz == size()) { return; }
        if (sz > size())
        {
            ETL_ASSERT(sz <= capacity()
                       && "static_vector cannot be resized to "
                          "a size greater than capacity");
            insert(end(), sz - size(), value);
        }
        else
        {
            erase(end() - (size() - sz), end());
        }
    }

private:
    template <typename It>
    constexpr void assert_iterator_in_range([[maybe_unused]] It it) noexcept
    {
        static_assert(etl::is_pointer_v<It>);
        ETL_ASSERT(this->begin() <= it && "iterator not in range");
        ETL_ASSERT(it <= end() && "iterator not in range");
    }

    template <typename It0, typename It1>
    constexpr void assert_valid_iterator_pair([[maybe_unused]] It0 first,
                                              [[maybe_unused]] It1 last) noexcept
    {
        static_assert(etl::is_pointer_v<It0>);
        static_assert(etl::is_pointer_v<It1>);
        ETL_ASSERT(first <= last && "invalid iterator pair");
    }

    template <typename It0, typename It1>
    constexpr void assert_iterator_pair_in_range([[maybe_unused]] It0 first,
                                                 [[maybe_unused]] It1 last) noexcept
    {
        assert_iterator_in_range(first);
        assert_iterator_in_range(last);
        assert_valid_iterator_pair(first, last);
    }
};

/**
 * @brief
 */
template <typename T, size_t Capacity>
constexpr auto operator==(static_vector<T, Capacity> const& lhs,
                          static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    if (etl::size(lhs) == etl::size(rhs))
    {
        return etl::equal(etl::begin(lhs), etl::end(lhs), etl::begin(rhs), etl::end(rhs),
                          etl::equal_to<> {});
    }
    return false;
}

/**
 * @brief
 */
template <typename T, size_t Capacity>
constexpr auto operator<(static_vector<T, Capacity> const& lhs,
                         static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return etl::equal(etl::begin(lhs), etl::end(lhs), etl::begin(rhs), etl::end(rhs),
                      etl::less<> {});
}

/**
 * @brief
 */
template <typename T, size_t Capacity>
constexpr auto operator!=(static_vector<T, Capacity> const& lhs,
                          static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return not(lhs == rhs);
}

/**
 * @brief
 */
template <typename T, size_t Capacity>
constexpr auto operator<=(static_vector<T, Capacity> const& lhs,
                          static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return etl::equal(etl::begin(lhs), etl::end(lhs), etl::begin(rhs), etl::end(rhs),
                      etl::less_equal<> {});
}

/**
 * @brief
 */
template <typename T, size_t Capacity>
constexpr auto operator>(static_vector<T, Capacity> const& lhs,
                         static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return etl::equal(etl::begin(lhs), etl::end(lhs), etl::begin(rhs), etl::end(rhs),
                      etl::greater<> {});
}

/**
 * @brief
 */
template <typename T, size_t Capacity>
constexpr auto operator>=(static_vector<T, Capacity> const& lhs,
                          static_vector<T, Capacity> const& rhs) noexcept -> bool
{
    return etl::equal(etl::begin(lhs), etl::end(lhs), etl::begin(rhs), etl::end(rhs),
                      etl::greater_equal<> {});
}

}  // namespace etl

#endif  // TAETL_STATIC_VECTOR_HPP
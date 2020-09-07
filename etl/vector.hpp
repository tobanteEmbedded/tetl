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

/**
 * @example vector.cpp
 */

#ifndef TAETL_VECTOR_HPP
#define TAETL_VECTOR_HPP

#include "etl/algorithm.hpp"    // for for_each
#include "etl/definitions.hpp"  // for size_t, ptrdiff_t
#include "etl/new.hpp"          // for operator new
#include "etl/utility.hpp"      // for forward

namespace etl
{
template <class ValueType, size_t Capacity>
class stack_vector
{
public:
    using value_type      = ValueType;
    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;
    using reference       = ValueType&;
    using const_reference = ValueType const&;
    using pointer         = ValueType*;
    using const_pointer   = ValueType const*;
    using iterator        = ValueType*;
    using const_iterator  = ValueType const*;
    // using reverse_iterator       = etl::reverse_iterator<iterator>;
    // using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    /**
     * @brief Default constructor. Constructs an empty container.
     */
    constexpr stack_vector() noexcept : memory_ {0}, size_ {0} { }

    /**
     * @brief Constructs the container with count default-inserted instances of
     * T. No copies are made.
     */
    explicit constexpr stack_vector(size_type count) : stack_vector {}
    {
        for (auto i = size_type {0}; i < count; ++i) { emplace_back(); }
    }

    /**
     * @brief Constructs the container with count copies of elements with value
     * value.
     */
    constexpr stack_vector(size_type count, const_reference value)
        : stack_vector {}
    {
        for (auto i = size_type {0}; i < count; ++i) { push_back(value); }
    }

    /**
     * @brief Copy constructor. Constructs the container with the copy of the
     * contents of other.
     */
    constexpr stack_vector(stack_vector const& other) : stack_vector {}
    {
        etl::for_each(other.begin(), other.end(), [&](auto const element) {
            push_back(etl::move(element));
        });
    }

    /**
     * @brief Move constructor. Constructs the container with the contents of
     * other using move semantics. Allocator is obtained by move-construction
     * from the allocator belonging to other. After the move, other is
     * guaranteed to be empty().
     */
    constexpr stack_vector(stack_vector&& other) noexcept : stack_vector {}
    {
        etl::for_each(other.begin(), other.end(),
                      [&](auto element) { emplace_back(etl::move(element)); });
        other.clear();
    }

    /**
     * @brief Replaces the contents of the container. Copy assignment operator.
     * Replaces the contents with a copy of the contents of other.
     */
    constexpr auto operator=(stack_vector const& other) -> stack_vector&
    {
        etl::for_each(other.begin(), other.end(), [&](auto const element) {
            push_back(etl::move(element));
        });
        return *this;
    }

    /**
     * @brief Replaces the contents of the container. Move assignment operator.
     * Replaces the contents with those of other using move semantics (i.e. the
     * data in other is moved from other into this container). other is in a
     * valid but unspecified state afterwards.
     */
    constexpr auto operator=(stack_vector&& other) -> stack_vector&
    {
        etl::for_each(other.begin(), other.end(),
                      [&](auto element) { emplace_back(etl::move(element)); });
        other.clear();
        return *this;
    }

    /**
     * @brief Destructs the vector. The destructors of the elements are called
     * and the used storage is deallocated. Note, that if the elements are
     * pointers, the pointed-to objects are not destroyed.
     */
    ~stack_vector() { clear(); }

    /**
     * @brief Replaces the contents of the container. Replaces the contents with
     * count copies of value value.
     */
    constexpr auto assign(size_type count, const_reference value) -> void
    {
        clear();
        for (auto i = size_type {0}; i < count; ++i) { push_back(value); }
    }

    /**
     * @brief Returns a reference to the first element in the container. Calling
     * front on an empty container is undefined.
     */
    [[nodiscard]] constexpr auto front() -> reference
    {
        assert(!empty());
        return *(begin());
    }

    /**
     * @brief Returns a reference to the first element in the container. Calling
     * front on an empty container is undefined.
     */
    [[nodiscard]] constexpr auto front() const -> const_reference
    {
        assert(!empty());
        return *(begin());
    }

    /**
     * @brief Returns reference to the last element in the container. Calling
     * back on an empty container causes undefined behavior.
     */
    [[nodiscard]] constexpr auto back() -> reference
    {
        assert(!empty());
        return *(begin() + size_ - 1);
    }

    /**
     * @brief Returns reference to the last element in the container. Calling
     * back on an empty container causes undefined behavior.
     */
    [[nodiscard]] constexpr auto back() const -> const_reference
    {
        assert(!empty());
        return *(begin() + size_ - 1);
    }

    /**
     * @brief Returns a reference to the element at specified location pos. No
     * bounds checking is performed.
     */
    constexpr auto operator[](size_type pos) -> reference
    {
        assert(pos < size());
        return begin()[pos];
    }

    /**
     * @brief Returns a reference to the element at specified location pos. No
     * bounds checking is performed.
     */
    constexpr auto operator[](size_type pos) const -> const_reference
    {
        assert(pos < size());
        return begin()[pos];
    }

    /**
     * @brief Returns a reference to the element at specified location pos, with
     * bounds checking. If pos is not within the range of the container, an
     * exception of type etl::out_of_range is thrown.
     */
    constexpr auto at(size_type pos) -> reference
    {
        // if (!(pos < size()))
        // { throw etl::out_of_range {"index is out of range"}; }
        return (*this)[pos];
    }

    /**
     * @brief Returns a reference to the element at specified location pos, with
     * bounds checking. If pos is not within the range of the container, an
     * exception of type etl::out_of_range is thrown.
     */
    constexpr auto at(size_type pos) const -> const_reference
    {
        // if (!(pos < size()))
        // { throw etl::out_of_range {"index is out of range"}; }
        return (*this)[pos];
    }

    /**
     * @brief Returns pointer to the underlying array serving as element
     * storage. The pointer is such that range [data(); data() + size()) is
     * always a valid range, even if the container is empty (data() is not
     * dereferenceable in that case).
     */
    [[nodiscard]] constexpr auto data() noexcept -> pointer { return begin(); }

    /**
     * @brief Returns pointer to the underlying array serving as element
     * storage. The pointer is such that range [data(); data() + size()) is
     * always a valid range, even if the container is empty (data() is not
     * dereferenceable in that case).
     */
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
    {
        return begin();
    }

    /**
     * @brief Returns an iterator to the first element of the vector. If the
     * vector is empty, the returned iterator will be equal to end().
     */
    [[nodiscard]] constexpr auto begin() noexcept -> iterator
    {
        return (iterator)memory_;
    }

    /**
     * @brief Returns an iterator to the first element of the vector. If the
     * vector is empty, the returned iterator will be equal to end().
     */
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return (const_iterator)memory_;
    }

    /**
     * @brief Returns an iterator to the first element of the vector. If the
     * vector is empty, the returned iterator will be equal to end().
     */
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return begin();
    }

    /**
     * @brief Returns an iterator to the element following the last element of
     * the vector. This element acts as a placeholder; attempting to access it
     * results in undefined behavior.
     */
    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        return (iterator)(memory_ + (sizeof(value_type) * size_));
    }

    /**
     * @brief Returns an iterator to the element following the last element of
     * the vector. This element acts as a placeholder; attempting to access it
     * results in undefined behavior.
     */
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return (const_iterator)(memory_ + (sizeof(value_type) * size_));
    }

    /**
     * @brief Returns an iterator to the element following the last element of
     * the vector. This element acts as a placeholder; attempting to access it
     * results in undefined behavior.
     */
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return end();
    }

    /**
     * @brief Checks if the container has no elements, i.e. whether begin() ==
     * end().
     */
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size_ == 0;
    }

    /**
     * @brief Returns the number of elements in the container, i.e.
     * etl::distance(begin(), end()).
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return size_;
    }

    /**
     * @brief Returns the maximum number of elements the container is able to
     * hold.
     */
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return Capacity;
    }

    /**
     * @brief Returns the number of elements that the container has currently
     * allocated space for.
     */
    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type
    {
        return Capacity;
    }

    /**
     * @brief Erases all elements from the container. After this call, size()
     * returns zero.
     */
    constexpr auto clear() noexcept -> void
    {
        etl::for_each(begin(), end(),
                      [](value_type& element) { element.~value_type(); });
        size_ = 0;
    }

    /**
     * @brief Appends the given element to the end of the container. The new
     * element is initialized as a copy.
     */
    constexpr auto push_back(const_reference element) -> void
    {
        check_capacity();
        *((pointer)&memory_[sizeof(value_type) * size_++]) = etl::move(element);
    }

    /**
     * @brief Appends the given element to the end of the container. The value
     * is moved into the new element.
     */
    constexpr auto push_back(value_type&& element) -> void
    {
        check_capacity();
        *((pointer)&memory_[sizeof(value_type) * size_++]) = etl::move(element);
    }

    /**
     * @brief Appends a new element to the end of the container. The element is
     * constructed using placement-new to construct the element in-place at the
     * location provided by the container. The arguments args... are forwarded
     * to the constructor as etl::forward<Args>(args)....
     */
    template <class... Args>
    constexpr auto emplace_back(Args&&... args) -> reference
    {
        check_capacity();
        auto const size  = sizeof(value_type) * size_++;
        auto* const addr = reinterpret_cast<void*>(&memory_[size]);
        return *::new (addr) value_type {etl::forward<Args>(args)...};
    }

private:
    auto check_capacity() -> void
    {
        if (size_ == Capacity) { assert(false); }
    }

    alignas(value_type) etl::uint8_t memory_[Capacity * sizeof(value_type)];
    size_type size_;
};
}  // namespace etl
#endif  // TAETL_VECTOR_HPP

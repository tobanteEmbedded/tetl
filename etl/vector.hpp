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

#ifndef TAETL_VECTOR_HPP
#define TAETL_VECTOR_HPP

#include "etl/definitions.hpp"
#include "etl/utility.hpp"

namespace etl
{
template <typename ValueType>
class vector
{
public:
    using value_type = ValueType;

    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;

    using pointer       = ValueType*;
    using const_pointer = const ValueType*;

    using reference       = ValueType&;
    using const_reference = const ValueType&;

    using iterator       = ValueType*;
    using const_iterator = const ValueType*;

    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size_ == 0;
    }

    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return size_;
    }

    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return capacity_;
    }

    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type
    {
        return capacity_;
    }

    [[nodiscard]] constexpr auto data() noexcept -> pointer { return data_; }

    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
    {
        return data_;
    }

    /**
     * @brief Returns an iterator to the beginning.
     */
    [[nodiscard]] constexpr auto begin() noexcept -> iterator { return data_; }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return data_;
    }

    /**
     * @brief Returns an iterator to the end.
     */
    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        return data_ + size();
    }

    /**
     * @brief Returns an const iterator to the end.
     */
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return data_ + size();
    }

    /**
     * @brief Accesses the first item.
     */
    [[nodiscard]] constexpr auto front() noexcept -> reference
    {
        return data_[0];
    }

    /**
     * @brief Accesses the last item.
     */
    [[nodiscard]] constexpr auto back() noexcept -> reference
    {
        return data_[size_ - 1];
    }

    /**
     * @brief Adds one element to the back. It fails silently if the Array is
     * full
     */
    constexpr auto push_back(ValueType const& value) noexcept -> void
    {
        if (size_ >= capacity_) { return; }

        data_[size_++] = value;
    }

    /**
     * @brief Decrements the size by 1.
     */
    constexpr void pop_back() noexcept
    {
        if (size_ > 0) { size_--; }
    }

    /**
     * @brief Construct element inplace at the end of the vector. The behavior
     * is undefined if the size == capacity.
     * @returns Reference to constructed element.
     */
    template <class... Args>
    auto emplace_back(Args&&... args) noexcept -> reference
    {
        auto* const addr = reinterpret_cast<void*>(&data_[size_++]);
        return *::new (addr) ValueType {etl::forward<Args>(args)...};
    }

    /**
     * @brief Deleted, since the buffer size is constant.
     */
    auto reserve(size_type new_cap) -> void = delete;

    /**
     * @brief Deleted, since the buffer size is constant.
     */
    auto shrink_to_fit() -> void = delete;

protected:
    explicit vector(ValueType* data, size_t size, size_t capacity)
        : data_(data), size_(size), capacity_(capacity)
    {
    }

private:
    ValueType* data_;
    size_t size_;
    size_t const capacity_;
};

namespace make
{
template <typename ValueType, size_t Size>
class vector : public ::etl::vector<ValueType>
{
public:
    explicit vector() : ::etl::vector<ValueType> {data_, 0, Size} { }

private:
    ValueType data_[Size];
};
}  // namespace make
}  // namespace etl
#endif  // TAETL_VECTOR_HPP

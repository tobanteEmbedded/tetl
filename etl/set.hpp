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

#ifndef TAETL_SET_HPP
#define TAETL_SET_HPP

#include "etl/algorithm.hpp"   // for lower_bound, rotate
#include "etl/functional.hpp"  // for less
#include "etl/iterator.hpp"    // for reverse_iterator
#include "etl/utility.hpp"     // for forward

namespace etl
{
template <typename Key, etl::size_t Capacity, typename Compare = etl::less<Key>>
class static_set
{
public:
    using key_type               = Key;
    using value_type             = Key;
    using size_type              = etl::size_t;
    using difference_type        = etl::ptrdiff_t;
    using key_compare            = Compare;
    using value_compare          = Compare;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using pointer                = value_type*;
    using const_pointer          = value_type const*;
    using iterator               = pointer;
    using const_iterator         = const_pointer;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    template <typename Iter>
    struct insert_return_type
    {
        Iter position;
        bool inserted;
    };

    static_set() = default;

    [[nodiscard]] constexpr auto begin() noexcept -> iterator { return data_; }
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return data_;
    }
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return begin();
    }

    [[nodiscard]] constexpr auto end() noexcept -> iterator { return data_ + size_; }
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return data_ + size_;
    }
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
    {
        return reverse_iterator(end());
    }
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return reverse_iterator(end());
    }
    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator
    {
        return rbegin();
    }

    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
    {
        return reverse_iterator(begin());
    }
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return reverse_iterator(begin());
    }
    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator
    {
        return rend();
    }

    /**
     * @brief Checks if the container has no elements, i.e. whether begin() == end().
     */
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return begin() == end();
    }

    /**
     * @brief Checks if the container full, i.e. whether size() == Capacity.
     */
    [[nodiscard]] constexpr auto full() const noexcept -> bool
    {
        return size_ == Capacity;
    }

    /**
     * @brief Returns the number of elements in the container, i.e. std::distance(begin(),
     * end()).
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return size_; }

    /**
     * @brief Returns the maximum number of elements the container is able to hold.
     */
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return Capacity;
    }

    /**
     * @brief Inserts element into the container, if the container doesn't
     * already contain an element with an equivalent key.
     */
    auto insert(value_type&& value) -> etl::pair<iterator, bool>
    {
        if (!full())
        {
            auto p = etl::lower_bound(begin(), end(), value);
            if (p == end() || *(p) != value)
            {
                data_[size_++] = etl::move(value);
                auto pos       = etl::rotate(p, end() - 1, end());
                return etl::make_pair(pos, true);
            }
        }

        return etl::pair<iterator, bool>(nullptr, true);
    }

    /**
     * @brief Inserts element into the container, if the container doesn't
     * already contain an element with an equivalent key.
     */
    auto insert(value_type const& value) -> etl::pair<iterator, bool>
    {
        value_type tmp = value;
        return insert(etl::move(tmp));
    }

    /**
     * @brief Inserts a new element into the container constructed in-place with
     * the given args if there is no element with the key in the container.
     */
    template <class... Args>
    auto emplace(Args&&... args) -> etl::pair<iterator, bool>
    {
        return insert(value_type(etl::forward<Args>(args)...));
    }

    /**
     * @brief Finds an element with key equivalent to key.
     *
     * @return Iterator to an element with key equivalent to key. If no such
     * element is found, past-the-end (see end()) iterator is returned.
     */
    [[nodiscard]] constexpr auto find(key_type const& key) noexcept -> iterator
    {
        return etl::find(begin(), end(), key);
    }

    /**
     * @brief Finds an element with key equivalent to key.
     *
     * @return Iterator to an element with key equivalent to key. If no such
     * element is found, past-the-end (see end()) iterator is returned.
     */
    [[nodiscard]] constexpr auto find(key_type const& key) const noexcept
        -> const_iterator
    {
        return etl::find(begin(), end(), key);
    }

    /**
     * @brief Checks if there is an element with key equivalent to key in the
     * container.
     */
    [[nodiscard]] constexpr auto contains(key_type const& key) const noexcept -> bool
    {
        return find(key) != end();
    }

    /**
     * @brief Returns the function object that compares the keys, which is a copy
     * of this container's constructor argument comp. It is the same as
     * value_comp.
     *
     * @return The key comparison function object.
     */
    [[nodiscard]] constexpr auto key_comp() const noexcept -> key_compare
    {
        return key_compare();
    }

    /**
     * @brief Returns the function object that compares the values. It is the same
     * as key_comp.
     *
     * @return The value comparison function object.
     */
    [[nodiscard]] constexpr auto value_comp() const noexcept -> value_compare
    {
        return value_compare();
    }

private:
    key_type data_[Capacity] {};
    size_type size_ {};
};
}  // namespace etl

#endif  // TAETL_SET_HPP
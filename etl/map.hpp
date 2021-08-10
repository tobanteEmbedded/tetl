// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_MAP_HPP
#define TETL_MAP_HPP

#include "etl/version.hpp"

#include "etl/_algorithm/find_if.hpp"
#include "etl/_algorithm/for_each.hpp"
#include "etl/_assert/macro.hpp"

#include "etl/cstddef.hpp"
#include "etl/functional.hpp"
#include "etl/set.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

namespace etl {
/// \brief Interface base struct for etl::map. Use this struct for function
/// parameters. To create an instance, use etl::map.
/// \module Containers
template <typename KeyType, typename ValueType,
    typename Compare = etl::less<KeyType>>
struct map_view {
public:
    using key_type        = KeyType;
    using mapped_type     = ValueType;
    using value_type      = etl::pair<KeyType const, ValueType>;
    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;
    using key_compare     = Compare;
    using reference       = value_type&;
    using const_reference = value_type const&;
    using pointer         = value_type*;
    using const_pointer   = value_type const*;
    using iterator        = value_type*;
    using const_iterator  = value_type const*;

    /// \brief Returns a reference to the mapped value of the element with key
    /// equivalent to key. If no such element exists, you are in UB land.
    [[nodiscard]] constexpr auto at(key_type const& key) -> mapped_type&
    {
        TETL_ASSERT(find(key) != nullptr);
        return find(key)->second;
    }

    /// \brief Returns a reference to the mapped value of the element with key
    /// equivalent to key. If no such element exists, you are in UB land.
    [[nodiscard]] constexpr auto at(key_type const& key) const
        -> mapped_type const&
    {
        TETL_ASSERT(find(key) != nullptr);
        return find(key)->second;
    }

    /// \brief Returns a reference to the value that is mapped to a key
    /// equivalent to key, performing an insertion if such key does not already
    /// exist.
    [[nodiscard]] constexpr auto operator[](key_type const& key) -> mapped_type&
    {
        auto const item = find(key);
        if (item == nullptr) {
            auto const res = insert(value_type { key, {} });
            return res.first->second;
        }
        return item->second;
    }

    /// \brief Returns an iterator to the beginning.
    [[nodiscard]] constexpr auto begin() noexcept -> iterator { return data_; }

    /// \brief Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return data_;
    }

    /// \brief Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return data_;
    }

    /// \brief Returns an iterator to the end.
    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        return data_ + size();
    }

    /// \brief Returns an const iterator to the end.
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return data_ + size();
    }

    /// \brief Returns an const iterator to the end.
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return data_ + size();
    }

    /// \brief Returns the current element count.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return size_;
    }

    /// \brief Returns the capacity.
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return capacity_;
    }

    /// \brief Returns true if the size == 0.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size_ == 0;
    }

    /// \brief Returns 1 if the key is present, otherwise 0.
    [[nodiscard]] constexpr auto count(key_type const& key) const noexcept
        -> size_type
    {
        return find(key) != nullptr ? 1 : 0;
    }

    /// \brief  Checks if there is an element with key equivalent to key in the
    /// container.
    [[nodiscard]] constexpr auto contains(key_type const& key) const -> bool
    {
        return find(key) != nullptr;
    }

    /// \brief Erases all elements from the container. After this call, size()
    /// returns zero.
    constexpr auto clear() noexcept -> void
    {
        etl::for_each(begin(), end(), [](auto& value) { value.~value_type(); });
        size_ = 0;
    }

    /// \brief Inserts a value pair into the map.
    ///
    /// \details Returns a pair consisting of an iterator to the inserted
    /// element (or to the element that prevented the insertion) and a bool
    /// denoting whether the insertion took place.
    constexpr auto insert(value_type const& value) noexcept
        -> etl::pair<iterator, bool>
    {
        if (size_ == capacity_) { return { end(), false }; }

        auto* const addr = reinterpret_cast<void*>(&data_[size_++]);
        ::new (addr) value_type { value };
        return { &data_[size_], true };
    }

    /// \brief Inserts a value pair into the map.
    ///
    /// \details Returns a pair consisting of an iterator to the inserted
    /// element (or to the element that prevented the insertion) and a bool
    /// denoting whether the insertion took place.
    template <typename P, TETL_REQUIRES_(is_constructible_v<value_type, P&&>)>
    constexpr auto insert(P&& value) -> etl::pair<iterator, bool>
    {
        return emplace(etl::forward<P>(value));
    }

    /// \brief Inserts a value pair into the map.
    ///
    /// \details Returns a pair consisting of an iterator to the inserted
    /// element (or to the element that prevented the insertion) and a bool
    /// denoting whether the insertion took place.
    constexpr auto insert(value_type&& value) -> etl::pair<iterator, bool>
    {
        if (size_ == capacity_) { return { end(), false }; }

        auto* const addr = reinterpret_cast<void*>(&data_[size_++]);
        ::new (addr) value_type { etl::move(value) };
        return { &data_[size_], true };
    }

    /// \brief Inserts a new element into the container constructed in-place
    /// with the given args if there is no element with the key in the
    /// container.
    ///
    /// \details Careful use of emplace allows the new element to be constructed
    /// while avoiding unnecessary copy or move operations. The constructor of
    /// the new element (i.e. etl::pair<Key const, T>) is called with exactly
    /// the same arguments as supplied to emplace, forwarded via
    /// etl::forward<Args>(args)....
    template <typename... Args>
    constexpr auto emplace(Args&&... args) -> etl::pair<iterator, bool>
    {
        // Return if no capacity is left.
        if (size_ == capacity_) { return { end(), false }; }

        // Construct value_type inplace at the end of the internal array.
        auto* const addr = reinterpret_cast<void*>(&data_[size_]);
        auto* obj = ::new (addr) value_type { etl::forward<Args>(args)... };

        // Check if the key from the newly created object has already existed.
        auto predicate
            = [&](auto const& item) { return item.first == obj->first; };
        auto* keyExisted = find_if(begin(), end(), predicate);

        // If so, return its iterator and false for insertion.
        if (keyExisted != end()) {
            obj->~value_type();
            return { keyExisted, false };
        }

        // Key has not existed before. Array needs to be sorted.
        size_++;
        return { obj, true };
    }

    /// \brief Returns an element with key equivalent to key. Nullptr if not
    /// found.
    [[nodiscard]] constexpr auto find(KeyType const& key) noexcept -> iterator
    {
        auto keysMatch = [&key](auto const& item) { return item.first == key; };
        auto iter      = etl::find_if(begin(), end(), keysMatch);
        return iter != end() ? iter : nullptr;
    }

    /// \brief Returns an element with key equivalent to key. Nullptr if not
    /// found.
    [[nodiscard]] constexpr auto find(KeyType const& key) const noexcept
        -> const_iterator
    {
        auto keysMatch = [&key](auto const& item) { return item.first == key; };
        auto iter      = etl::find_if(begin(), end(), keysMatch);
        return iter != end() ? iter : nullptr;
    }

protected:
    explicit constexpr map_view(pointer data, size_t capacity)
        : data_ { data }, size_ { 0 }, capacity_ { capacity }
    {
    }

private:
    pointer data_;
    size_type size_;
    size_type const capacity_;
};

/// \brief etl::map is a sorted associative container that contains key-value
/// pairs with unique keys. Keys are sorted by using the comparison function
/// Compare. Uses an inline key-value pair array as storage.
///
/// \details Everywhere the standard library uses the Compare requirements,
/// uniqueness is determined by using the equivalence relation. In imprecise
/// terms, two objects a and b are considered equivalent (not unique) if
/// neither compares less than the other: !comp(a, b) && !comp(b, a).
/// \module Containers
template <typename KeyT, typename ValueT, size_t Size,
    typename Compare = etl::less<KeyT>>
struct map : public map_view<KeyT, ValueT, Compare> {
    /// \brief Default constructor.
    constexpr explicit map() noexcept
        : base_t { reinterpret_cast<pair_t*>(&memory_[0]), Size }
    {
    }

    /// \brief Copy constructor. Constructs the container with the copy of the
    /// contents of other.
    constexpr map(map const& other) : map {}
    {
        etl::for_each(other.begin(), other.end(),
            [this](auto element) { this->base_t::insert(etl::move(element)); });
    }

    /// \brief Move constructor. Constructs the container with the contents of
    /// other using move semantics. Allocator is obtained by move-construction
    /// from the allocator belonging to other. After the move, other is
    /// guaranteed to be empty().
    constexpr map(map&& other) noexcept : map {}
    {
        etl::for_each(other.begin(), other.end(), [this](auto& element) {
            this->base_t::insert(etl::move(element));
        });
        other.clear();
    }

    /// \brief Replaces the contents of the container. Copy assignment operator.
    /// Replaces the contents with a copy of the contents of other.
    constexpr auto operator=(map const& other) -> map&
    {
        if (this == &other) { return *this; }

        etl::for_each(other.begin(), other.end(),
            [this](auto element) { this->base_t::insert(etl::move(element)); });
        return *this;
    }

    /// \brief Replaces the contents of the container. Move assignment operator.
    /// Replaces the contents with those of other using move semantics (i.e. the
    /// data in other is moved from other into this container). other is in a
    /// valid but unspecified state afterwards.
    constexpr auto operator=(map&& other) noexcept -> map&
    {
        etl::for_each(other.begin(), other.end(), [this](auto& element) {
            this->base_t::insert(etl::move(element));
        });
        other.clear();
        return *this;
    }

    /// \brief Destructor. Deletes all elements.
    ~map() noexcept { base_t::clear(); }

private:
    using base_t    = map_view<KeyT, ValueT, Compare>;
    using pair_t    = typename base_t::value_type;
    using storage_t = aligned_storage_t<sizeof(pair_t), alignof(pair_t)>;
    storage_t memory_[Size] {};
};

/// \module Containers
template <typename KeyT, typename ValueT, size_t Capacity,
    typename Compare = etl::less<KeyT>>
struct static_map {
private:
    struct compare_type {
        [[nodiscard]] constexpr auto operator()(pair<KeyT, ValueT> const& lhs,
            pair<KeyT, ValueT> const& rhs) const -> bool
        {
            return lhs.first < rhs.first;
        }
    };

    using storage_type = static_set<pair<KeyT, ValueT>, Capacity, compare_type>;
    storage_type memory_ {};

public:
    using key_type         = KeyT;
    using mapped_type      = ValueT;
    using key_compare      = Compare;
    using value_type       = typename storage_type::value_type;
    using size_type        = typename storage_type::size_type;
    using difference_type  = typename storage_type::difference_type;
    using reference        = typename storage_type::reference;
    using const_reference  = typename storage_type::const_reference;
    using pointer          = typename storage_type::pointer;
    using const_pointer    = typename storage_type::const_pointer;
    using iterator         = typename storage_type::iterator;
    using const_iterator   = typename storage_type::const_iterator;
    using reverse_iterator = typename storage_type::reverse_iterator;
    using const_reverse_iterator =
        typename storage_type::const_reverse_iterator;

    struct value_compare {
    public:
        [[nodiscard]] constexpr auto operator()(
            value_type const& x, value_type const& y) const -> bool
        {
            return comp(x.first, y.first);
        }

    protected:
        Compare comp;
        value_compare(Compare c) : comp(c) { }

    private:
        friend struct static_map;
    };

    /// \brief Returns an iterator to the beginning.
    [[nodiscard]] constexpr auto begin() noexcept -> iterator
    {
        return memory_.begin();
    }

    /// \brief Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return memory_.begin();
    }

    /// \brief Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return memory_.begin();
    }

    /// \brief Returns an iterator to the end.
    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        return memory_.end();
    }

    /// \brief Returns an const iterator to the end.
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return memory_.end();
    }

    /// \brief Returns an const iterator to the end.
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return memory_.end();
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// map. It corresponds to the last element of the non-reversed map. If the
    /// map is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
    {
        return memory_.rbegin();
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// map. It corresponds to the last element of the non-reversed map. If the
    /// map is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto rbegin() const noexcept
        -> const_reverse_iterator
    {
        return memory_.rbegin();
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// map. It corresponds to the last element of the non-reversed map. If the
    /// map is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto crbegin() const noexcept
        -> const_reverse_iterator
    {
        return memory_.crbegin();
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed map. It corresponds to the element preceding the
    /// first element of the non-reversed map. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
    {
        return memory_.rend();
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed map. It corresponds to the element preceding the
    /// first element of the non-reversed map. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return memory_.rend();
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed map. It corresponds to the element preceding the
    /// first element of the non-reversed map. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto crend() const noexcept
        -> const_reverse_iterator
    {
        return memory_.crend();
    }

    /// \brief Checks if the container has no elements.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return memory_.empty();
    }

    /// \brief Returns the number of elements in the container.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return memory_.size();
    }

    /// \brief Checks if the container full, i.e. whether size() == Capacity.
    [[nodiscard]] constexpr auto full() const noexcept -> bool
    {
        return memory_.full();
    }

    /// \brief Returns the maximum number of elements the container is able to
    /// hold, i.e. max_size() == Capacity.
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return memory_.max_size();
    }

    /// \brief Erases all elements from the container. After this call, size()
    /// returns zero. Invalidates any references, pointers, or iterators
    /// referring to contained elements. Any past-the-end iterator remains
    /// valid.
    constexpr auto clear() noexcept -> void { memory_.clear(); }

    /// \brief Inserts a new element into the container constructed in-place
    /// with the given args if there is no element with the key in the
    /// container.
    template <typename... Args>
    constexpr auto emplace(Args&&... args) -> pair<iterator, bool>
    {
        return memory_.emplace(forward<Args>(args)...);
    }

    /// \brief Inserts element(s) into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    constexpr auto insert(value_type const& value) -> pair<iterator, bool>
    {
        value_type copy = value;
        return insert(move(copy));
    }

    /// \brief Inserts element(s) into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    template <typename P, TETL_REQUIRES_(is_convertible_v<value_type, P&&>)>
    constexpr auto insert(P&& value) -> pair<iterator, bool>
    {
        return emplace(forward<P>(value));
    }

    /// \brief Inserts element(s) into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    constexpr auto insert(value_type&& value) -> pair<iterator, bool>
    {
        return memory_.insert(move(value));
    }

    /// \brief Inserts element(s) into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    constexpr auto insert(const_iterator hint, value_type const& value)
        -> iterator
    {
        ignore_unused(hint);
        return insert(value).first;
    }

    template <typename P, TETL_REQUIRES_(is_convertible_v<value_type, P&&>)>
    constexpr auto insert(const_iterator hint, P&& value) -> iterator
    {
        ignore_unused(hint);
        return emplace(value).first;
    }

    /// \brief Inserts element(s) into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    constexpr auto insert(const_iterator hint, value_type&& value) -> iterator
    {
        ignore_unused(hint);
        return insert(value).first;
    }

    /// \brief Inserts element(s) into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    template <typename InputIter>
    constexpr auto insert(InputIter first, InputIter last) -> void
    {
        for_each(first, last, [&](auto const& value) { insert(value); });
    }

    [[nodiscard]] constexpr auto key_comp() const -> key_compare
    {
        return key_compare {};
    }

    [[nodiscard]] constexpr auto value_comp() const -> value_compare
    {
        return value_compare { key_comp() };
    }
};
} // namespace etl
#endif // TETL_MAP_HPP

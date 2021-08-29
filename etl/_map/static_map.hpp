/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MAP_STATIC_MAP_HPP
#define TETL_MAP_STATIC_MAP_HPP

#include "etl/_algorithm/find_if.hpp"
#include "etl/_algorithm/for_each.hpp"
#include "etl/_cassert/macro.hpp"
#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_new/operator.hpp"
#include "etl/_set/static_set.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

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
#endif // TETL_MAP_STATIC_MAP_HPP

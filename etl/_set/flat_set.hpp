/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MAP_FLAT_MAP_HPP
#define TETL_MAP_FLAT_MAP_HPP

#include "etl/_algorithm/equal.hpp"
#include "etl/_algorithm/lexicographical_compare.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/data.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_iterator/rbegin.hpp"
#include "etl/_iterator/rend.hpp"
#include "etl/_iterator/reverse_iterator.hpp"
#include "etl/_iterator/size.hpp"
#include "etl/_set/sorted_unique.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief A flat_multiset is a container adaptor that provides an associative
/// container interface that supports equivalent keys (possibly containing
/// multiple copies of the same key value) and provides for fast retrieval of
/// the keys themselves. flat_multiset supports random access iterators.
///
/// https://isocpp.org/files/papers/P1222R1.pdf
template <typename Key, typename Container, typename Compare = etl::less<Key>>
struct flat_set {
    using key_type               = Key;
    using key_compare            = Compare;
    using value_type             = Key;
    using value_compare          = Compare;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using size_type              = typename Container::size_type;
    using difference_type        = typename Container::difference_type;
    using iterator               = typename Container::iterator;
    using const_iterator         = typename Container::const_iterator;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;
    using container_type         = Container;

    flat_set() : flat_set(Compare()) { }

    /// \brief Initializes c with etl::move(cont), value-initializes compare,
    /// sorts the range [begin(),end()) with respect to compare, and finally
    /// erases the range [ranges::unique(*this, compare), end());
    ///
    /// Complexity: Linear in N if cont is sorted with respect to compare and
    /// otherwise N log N, where N is cont.size().
    explicit flat_set(container_type);

    flat_set(etl::sorted_unique_t /*tag*/, container_type cont)
        : container_ { etl::move(cont) }, compare_ { Compare() }
    {
    }

    explicit flat_set(Compare const& comp) : container_ {}, compare_(comp) { }

    template <typename InputIt>
    flat_set(InputIt first, InputIt last, Compare const& comp = Compare())
        : container_ {}, compare_ { comp }
    {
        insert(first, last);
    }

    template <typename InputIt>
    flat_set(etl::sorted_unique_t /*tag*/, InputIt first, InputIt last,
        Compare const& comp = Compare())
        : container_ { first, last }, compare_ { comp }
    {
    }

    [[nodiscard]] constexpr auto begin() noexcept -> iterator
    {
        return container_.begin();
    }

    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return container_.begin();
    }

    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return container_.begin();
    }

    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        return container_.end();
    }

    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return container_.end();
    }

    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return container_.begin();
    }

    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
    {
        return reverse_iterator(end());
        ;
    }

    [[nodiscard]] constexpr auto rbegin() const noexcept
        -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    [[nodiscard]] constexpr auto crbegin() const noexcept
        -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
    {
        return reverse_iterator(begin());
    }

    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    [[nodiscard]] constexpr auto crend() const noexcept
        -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /// \brief Returns true if the underlying container is empty.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return container_.empty();
    }

    /// \brief Returns the size of the underlying container.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return container_.size();
    }

    /// \brief Returns the max_size of the underlying container.
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return container_.max_size();
    }

    // 21.6.5.3, modifiers
    template <typename... Args>
    constexpr auto emplace(Args&&... args) -> pair<iterator, bool>;

    template <typename... Args>
    constexpr auto emplace_hint(const_iterator position, Args&&... args)
        -> iterator;

    constexpr auto insert(value_type const& x) -> pair<iterator, bool>
    {
        return emplace(x);
    }

    constexpr auto insert(value_type&& x) -> pair<iterator, bool>
    {
        return emplace(etl::move(x));
    }

    constexpr auto insert(const_iterator position, value_type const& x)
        -> iterator
    {
        return emplace_hint(position, x);
    }

    constexpr auto insert(const_iterator position, value_type&& x) -> iterator
    {
        return emplace_hint(position, etl::move(x));
    }

    template <typename InputIt>
    constexpr auto insert(InputIt first, InputIt last) -> void;
    template <typename InputIt>
    constexpr auto insert(
        etl::sorted_unique_t /*tag*/, InputIt first, InputIt last) -> void;

    constexpr auto extract() && -> container_type;

    constexpr auto replace(container_type&&) -> void;

    constexpr auto erase(iterator position) -> iterator;
    constexpr auto erase(const_iterator position) -> iterator;
    constexpr auto erase(key_type const& x) -> size_type;
    constexpr auto erase(const_iterator first, const_iterator last) -> iterator;

    constexpr auto swap(flat_set& fs) noexcept(
        etl::is_nothrow_swappable_v<key_compare>) -> void;
    constexpr auto clear() noexcept -> void;

    // observers
    [[nodiscard]] constexpr auto key_comp() const -> key_compare;
    [[nodiscard]] constexpr auto value_comp() const -> value_compare;

    // set operations
    [[nodiscard]] constexpr auto find(key_type const& x) -> iterator;
    [[nodiscard]] constexpr auto find(key_type const& x) const
        -> const_iterator;
    template <typename K>
    [[nodiscard]] constexpr auto find(K const& x) -> iterator;
    template <typename K>
    [[nodiscard]] constexpr auto find(K const& x) const -> const_iterator;

    [[nodiscard]] constexpr auto count(key_type const& x) const -> size_type;
    template <typename K>
    [[nodiscard]] constexpr auto count(K const& x) const -> size_type;

    [[nodiscard]] constexpr auto contains(key_type const& x) const -> bool;
    template <typename K>
    [[nodiscard]] constexpr auto contains(K const& x) const -> bool;

    [[nodiscard]] constexpr auto lower_bound(key_type const& x) -> iterator;
    [[nodiscard]] constexpr auto lower_bound(key_type const& x) const
        -> const_iterator;
    template <typename K>
    [[nodiscard]] constexpr auto lower_bound(K const& x) -> iterator;
    template <typename K>
    [[nodiscard]] constexpr auto lower_bound(K const& x) const
        -> const_iterator;

    [[nodiscard]] constexpr auto upper_bound(key_type const& x) -> iterator;
    [[nodiscard]] constexpr auto upper_bound(key_type const& x) const
        -> const_iterator;
    template <typename K>
    [[nodiscard]] constexpr auto upper_bound(K const& x) -> iterator;
    template <typename K>
    [[nodiscard]] constexpr auto upper_bound(K const& x) const
        -> const_iterator;

    [[nodiscard]] constexpr auto equal_range(key_type const& x)
        -> pair<iterator, iterator>;
    [[nodiscard]] constexpr auto equal_range(key_type const& x) const
        -> pair<const_iterator, const_iterator>;
    template <typename K>
    [[nodiscard]] constexpr auto equal_range(K const& x)
        -> pair<iterator, iterator>;
    template <typename K>
    [[nodiscard]] constexpr auto equal_range(K const& x) const
        -> pair<const_iterator, const_iterator>;

private:
    container_type container_;
    key_compare compare_;
};

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator==(
    flat_set<Key, Container, Compare> const& x,
    flat_set<Key, Container, Compare> const& y) -> bool
{
    return etl::equal(x.begin(), x.end(), y.begin(), y.end());
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator!=(
    flat_set<Key, Container, Compare> const& x,
    flat_set<Key, Container, Compare> const& y) -> bool
{
    return !(x == y);
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator<(
    flat_set<Key, Container, Compare> const& x,
    flat_set<Key, Container, Compare> const& y) -> bool
{
    return etl::lexicographical_compare(x.begin(), x.end(), y.begin(), y.end());
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator>(
    flat_set<Key, Container, Compare> const& x,
    flat_set<Key, Container, Compare> const& y) -> bool
{
    return y < x;
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator<=(
    flat_set<Key, Container, Compare> const& x,
    flat_set<Key, Container, Compare> const& y) -> bool
{
    return !(y < x);
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator>=(
    flat_set<Key, Container, Compare> const& x,
    flat_set<Key, Container, Compare> const& y) -> bool
{
    return !(x < y);
}

template <typename Key, typename Container, typename Compare>
constexpr auto swap(flat_set<Key, Container, Compare>& x,
    flat_set<Key, Container, Compare>& y) noexcept(noexcept(x.swap(y))) -> void
{
    return x.swap(y);
}

} // namespace etl

#endif // TETL_MAP_FLAT_MAP_HPP

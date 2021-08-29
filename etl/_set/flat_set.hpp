/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MAP_FLAT_MAP_HPP
#define TETL_MAP_FLAT_MAP_HPP

#include "etl/_algorithm/equal.hpp"
#include "etl/_algorithm/lexicographical_compare.hpp"
#include "etl/_algorithm/partition_point.hpp"
#include "etl/_concepts/emulation.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_functional/is_transparent.hpp"
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

    flat_set() : flat_set { Compare {} } { }

    /// \brief Initializes c with etl::move(cont), value-initializes compare,
    /// sorts the range [begin(),end()) with respect to compare, and finally
    /// erases the range [ranges::unique(*this, compare), end());
    ///
    /// Complexity: Linear in N if cont is sorted with respect to compare and
    /// otherwise N log N, where N is cont.size().
    TETL_REQUIRES(detail::RandomAccessRange<container_type>)
    explicit flat_set(container_type const& container)
        : flat_set { etl::begin(container), etl::end(container), Compare() }
    {
    }

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
    constexpr auto emplace(Args&&... args) -> etl::pair<iterator, bool>
    {
        auto key    = Key { etl::forward<Args>(args)... };
        iterator it = lower_bound(key);

        if (it == end() || compare_(key, *it)) {
            it = container_.emplace(it, etl::move(key));
            return etl::make_pair(it, true);
        }

        return etl::make_pair(it, false);
    }

    template <typename... Args>
    constexpr auto emplace_hint(const_iterator /*position*/, Args&&... args)
        -> iterator
    {
        return emplace(etl::forward<Args>(args)...).first;
    }

    constexpr auto insert(value_type const& x) -> etl::pair<iterator, bool>
    {
        return emplace(x);
    }

    constexpr auto insert(value_type&& x) -> etl::pair<iterator, bool>
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
    constexpr auto insert(InputIt first, InputIt last) -> void
    {
        while (first != last) {
            insert(*first);
            ++first;
        }
    }

    template <typename InputIt>
    constexpr auto insert(
        etl::sorted_unique_t /*tag*/, InputIt first, InputIt last) -> void;

    constexpr auto extract() && -> container_type
    {
        auto&& container = etl::move(container_);
        clear();
        return container;
    }

    constexpr auto replace(container_type&& container) -> void
    {
        container_ = etl::move(container);
    }

    constexpr auto erase(iterator position) -> iterator
    {
        return container_.erase(position);
    }

    constexpr auto erase(const_iterator position) -> iterator
    {
        return container_.erase(position);
    }

    constexpr auto erase(key_type const& x) -> size_type;
    constexpr auto erase(const_iterator first, const_iterator last) -> iterator
    {
        return container_.erase(first, last);
    }

    constexpr auto swap(flat_set& other) noexcept(
        etl::is_nothrow_swappable_v<Container>&&
            etl::is_nothrow_swappable_v<Compare>) -> void
    {
        using etl::swap;
        swap(compare_, other.compare_);
        swap(container_, other.container_);
    }

    constexpr auto clear() noexcept -> void { container_.clear(); }

    // observers
    [[nodiscard]] constexpr auto key_comp() const -> key_compare
    {
        return compare_;
    }

    [[nodiscard]] constexpr auto value_comp() const -> value_compare
    {
        return compare_;
    }

    // set operations
    [[nodiscard]] constexpr auto find(key_type const& key) -> iterator
    {
        iterator it = lower_bound(key);
        if (it == end() || compare_(key, *it)) { return end(); }
        return it;
    }

    [[nodiscard]] constexpr auto find(key_type const& key) const
        -> const_iterator
    {
        const_iterator it = lower_bound(key);
        if (it == end() || compare_(key, *it)) { return end(); }
        return it;
    }

    template <typename K, TETL_REQUIRES_(detail::is_transparent_v<Compare>)>
    [[nodiscard]] constexpr auto find(K const& key) -> iterator
    {
        iterator it = lower_bound(key);
        if (it == end() || compare_(key, *it)) { return end(); }
        return it;
    }

    template <typename K, TETL_REQUIRES_(detail::is_transparent_v<Compare>)>
    [[nodiscard]] constexpr auto find(K const& key) const -> const_iterator
    {
        const_iterator it = lower_bound(key);
        if (it == end() || compare_(key, *it)) { return end(); }
        return it;
    }

    [[nodiscard]] constexpr auto count(key_type const& x) const -> size_type;
    template <typename K>
    [[nodiscard]] constexpr auto count(K const& x) const -> size_type;

    [[nodiscard]] constexpr auto contains(key_type const& x) const -> bool;
    template <typename K>
    [[nodiscard]] constexpr auto contains(K const& x) const -> bool;

    [[nodiscard]] constexpr auto lower_bound(key_type const& key) -> iterator
    {
        auto cmp = [&](auto const& k) -> bool { return compare_(k, key); };
        return etl::partition_point(begin(), end(), cmp);
    }

    [[nodiscard]] constexpr auto lower_bound(key_type const& key) const
        -> const_iterator
    {
        auto cmp = [&](auto const& k) -> bool { return compare_(k, key); };
        return etl::partition_point(begin(), end(), cmp);
    }

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
        -> etl::pair<iterator, iterator>;
    [[nodiscard]] constexpr auto equal_range(key_type const& x) const
        -> etl::pair<const_iterator, const_iterator>;
    template <typename K>
    [[nodiscard]] constexpr auto equal_range(K const& x)
        -> etl::pair<iterator, iterator>;
    template <typename K>
    [[nodiscard]] constexpr auto equal_range(K const& x) const
        -> etl::pair<const_iterator, const_iterator>;

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

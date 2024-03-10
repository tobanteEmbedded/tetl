// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FLAT_SET_FLAT_SET_HPP
#define TETL_FLAT_SET_FLAT_SET_HPP

#include <etl/_algorithm/equal.hpp>
#include <etl/_algorithm/lexicographical_compare.hpp>
#include <etl/_algorithm/partition_point.hpp>
#include <etl/_concepts/emulation.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_flat_set/sorted_unique.hpp>
#include <etl/_functional/is_transparent.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_iterator/rbegin.hpp>
#include <etl/_iterator/rend.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_type_traits/is_nothrow_swappable.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/pair.hpp>

namespace etl {

/// \brief A flat_set is a container adaptor that provides an associative
/// container interface that supports unique keys (contains at most one of each
/// key value) and provides for fast retrieval of the keys themselves. flat_set
/// supports random access iterators. Any sequence container supporting random
/// access iteration can be used to instantiate flat_set
///
/// \details A flat_set satisfies all of the requirements of a container and of
/// a reversible container. flat_set satisfies the requirements of an
/// associative container, except that:
///
/// - it does not meet the requirements related to node handles,
/// - it does not meet the requirements related to iterator invalidation, and
/// - the time complexity of the insert, emplace, emplace_hint, and erase
/// members that respectively insert, emplace or erase a single element from the
/// set is linear, including the ones that take an insertion position iterator.
///
/// https://isocpp.org/files/papers/P1222R1.pdf
///
/// https://youtu.be/b9ZYM0d6htg
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

    constexpr flat_set() : flat_set {Compare {}} { }

    /// \brief Initializes c with etl::move(cont), value-initializes compare,
    /// sorts the range [begin(),end()) with respect to compare, and finally
    /// erases the range [ranges::unique(*this, compare), end());
    ///
    /// Complexity: Linear in N if cont is sorted with respect to compare and
    /// otherwise N log N, where N is cont.size().
    explicit constexpr flat_set(container_type const& container)
        requires(detail::RandomAccessRange<container_type>)
        : flat_set {etl::begin(container), etl::end(container), Compare()}
    {
    }

    constexpr flat_set(etl::sorted_unique_t /*tag*/, container_type cont)
        : _container {etl::move(cont)}, _compare {Compare()}
    {
    }

    explicit constexpr flat_set(Compare const& comp) : _container {}, _compare(comp) { }

    template <typename InputIt>
    constexpr flat_set(InputIt first, InputIt last, Compare const& comp = Compare()) : _container {}, _compare {comp}
    {
        insert(first, last);
    }

    template <typename InputIt>
    constexpr flat_set(etl::sorted_unique_t /*tag*/, InputIt first, InputIt last, Compare const& comp = Compare())
        : _container {first, last}, _compare {comp}
    {
    }

    [[nodiscard]] constexpr auto begin() noexcept -> iterator { return _container.begin(); }

    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator { return _container.begin(); }

    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator { return _container.begin(); }

    [[nodiscard]] constexpr auto end() noexcept -> iterator { return _container.end(); }

    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator { return _container.end(); }

    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return _container.begin(); }

    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator { return reverse_iterator(end()); }

    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator { return reverse_iterator(begin()); }

    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /// \brief Returns true if the underlying container is empty.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return _container.empty(); }

    /// \brief Returns the size of the underlying container.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return _container.size(); }

    /// \brief Returns the max_size of the underlying container.
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type { return _container.max_size(); }

    // 21.6.5.3, modifiers
    template <typename... Args>
    constexpr auto emplace(Args&&... args) -> etl::pair<iterator, bool>
    {
        auto key    = Key {etl::forward<Args>(args)...};
        iterator it = lower_bound(key);

        if (it == end() || _compare(key, *it)) {
            it = _container.emplace(it, etl::move(key));
            return etl::make_pair(it, true);
        }

        return etl::make_pair(it, false);
    }

    template <typename... Args>
    constexpr auto emplace_hint(const_iterator /*position*/, Args&&... args) -> iterator
    {
        return emplace(etl::forward<Args>(args)...).first;
    }

    constexpr auto insert(value_type const& x) -> etl::pair<iterator, bool> { return emplace(x); }

    constexpr auto insert(value_type&& x) -> etl::pair<iterator, bool> { return emplace(etl::move(x)); }

    constexpr auto insert(const_iterator position, value_type const& x) -> iterator
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
    constexpr auto insert(etl::sorted_unique_t /*tag*/, InputIt first, InputIt last) -> void;

    constexpr auto extract() && -> container_type
    {
        auto&& container = etl::move(_container);
        clear();
        return container;
    }

    constexpr auto replace(container_type&& container) -> void { _container = etl::move(container); }

    constexpr auto erase(iterator position) -> iterator { return _container.erase(position); }

    constexpr auto erase(const_iterator position) -> iterator { return _container.erase(position); }

    constexpr auto erase(key_type const& x) -> size_type;
    constexpr auto erase(const_iterator first, const_iterator last) -> iterator
    {
        return _container.erase(first, last);
    }

    constexpr auto swap(flat_set& other)
        noexcept(etl::is_nothrow_swappable_v<Container> && etl::is_nothrow_swappable_v<Compare>) -> void
    {
        using etl::swap;
        swap(_compare, other._compare);
        swap(_container, other._container);
    }

    constexpr auto clear() noexcept -> void { _container.clear(); }

    // observers
    [[nodiscard]] constexpr auto key_comp() const -> key_compare { return _compare; }

    [[nodiscard]] constexpr auto value_comp() const -> value_compare { return _compare; }

    // set operations
    [[nodiscard]] constexpr auto find(key_type const& key) -> iterator
    {
        iterator it = lower_bound(key);
        if (it == end() || _compare(key, *it)) { return end(); }
        return it;
    }

    [[nodiscard]] constexpr auto find(key_type const& key) const -> const_iterator
    {
        const_iterator it = lower_bound(key);
        if (it == end() || _compare(key, *it)) { return end(); }
        return it;
    }

    template <typename K>
        requires(detail::is_transparent_v<Compare>)
    [[nodiscard]] constexpr auto find(K const& key) -> iterator
    {
        iterator it = lower_bound(key);
        if (it == end() || _compare(key, *it)) { return end(); }
        return it;
    }

    template <typename K>
        requires(detail::is_transparent_v<Compare>)
    [[nodiscard]] constexpr auto find(K const& key) const -> const_iterator
    {
        const_iterator it = lower_bound(key);
        if (it == end() || _compare(key, *it)) { return end(); }
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
        auto cmp = [&](auto const& k) -> bool { return _compare(k, key); };
        return etl::partition_point(begin(), end(), cmp);
    }

    [[nodiscard]] constexpr auto lower_bound(key_type const& key) const -> const_iterator
    {
        auto cmp = [&](auto const& k) -> bool { return _compare(k, key); };
        return etl::partition_point(begin(), end(), cmp);
    }

    template <typename K>
    [[nodiscard]] constexpr auto lower_bound(K const& x) -> iterator;
    template <typename K>
    [[nodiscard]] constexpr auto lower_bound(K const& x) const -> const_iterator;

    [[nodiscard]] constexpr auto upper_bound(key_type const& x) -> iterator;
    [[nodiscard]] constexpr auto upper_bound(key_type const& x) const -> const_iterator;
    template <typename K>
    [[nodiscard]] constexpr auto upper_bound(K const& x) -> iterator;
    template <typename K>
    [[nodiscard]] constexpr auto upper_bound(K const& x) const -> const_iterator;

    [[nodiscard]] constexpr auto equal_range(key_type const& x) -> etl::pair<iterator, iterator>;
    [[nodiscard]] constexpr auto equal_range(key_type const& x) const -> etl::pair<const_iterator, const_iterator>;
    template <typename K>
    [[nodiscard]] constexpr auto equal_range(K const& x) -> etl::pair<iterator, iterator>;
    template <typename K>
    [[nodiscard]] constexpr auto equal_range(K const& x) const -> etl::pair<const_iterator, const_iterator>;

private:
    container_type _container;
    key_compare _compare;
};

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator==(
    flat_set<Key, Container, Compare> const& x, flat_set<Key, Container, Compare> const& y) -> bool
{
    return etl::equal(x.begin(), x.end(), y.begin(), y.end());
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator!=(
    flat_set<Key, Container, Compare> const& x, flat_set<Key, Container, Compare> const& y) -> bool
{
    return !(x == y);
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator<(
    flat_set<Key, Container, Compare> const& x, flat_set<Key, Container, Compare> const& y) -> bool
{
    return etl::lexicographical_compare(x.begin(), x.end(), y.begin(), y.end());
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator>(
    flat_set<Key, Container, Compare> const& x, flat_set<Key, Container, Compare> const& y) -> bool
{
    return y < x;
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator<=(
    flat_set<Key, Container, Compare> const& x, flat_set<Key, Container, Compare> const& y) -> bool
{
    return !(y < x);
}

template <typename Key, typename Container, typename Compare>
[[nodiscard]] constexpr auto operator>=(
    flat_set<Key, Container, Compare> const& x, flat_set<Key, Container, Compare> const& y) -> bool
{
    return !(x < y);
}

template <typename Key, typename Container, typename Compare>
constexpr auto swap(flat_set<Key, Container, Compare>& x, flat_set<Key, Container, Compare>& y)
    noexcept(noexcept(x.swap(y))) -> void
{
    return x.swap(y);
}

} // namespace etl

#endif // TETL_FLAT_SET_FLAT_SET_HPP

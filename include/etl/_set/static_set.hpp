// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SET_STATIC_SET_HPP
#define TETL_SET_STATIC_SET_HPP

#include "etl/_algorithm/lexicographical_compare.hpp"
#include "etl/_algorithm/lower_bound.hpp"
#include "etl/_algorithm/rotate.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/data.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_iterator/rbegin.hpp"
#include "etl/_iterator/rend.hpp"
#include "etl/_iterator/reverse_iterator.hpp"
#include "etl/_iterator/size.hpp"
#include "etl/_vector/static_vector.hpp"

namespace etl {
/// \brief static_set is an associative container that contains a sorted set
/// of unique objects of type Key. Sorting is done using the key comparison
/// function Compare.
template <typename Key, size_t Capacity, typename Compare = less<Key>>
struct static_set {
private:
    // TODO: Currently static_set only supports default constructible
    // comparators. This is because storing the Compare object would take up at
    // least 1 extra byte. Probably even more because of alignment. The fix is
    // to create a conditional storage struct depending on if the Compare
    // template argument can be default constructed. If so: construct it on
    // demand. If not: store it as a member.
    static_assert(is_default_constructible_v<Compare>);

    using storage_type = static_vector<Key, Capacity>;
    storage_type _memory {};

public:
    using key_type               = typename storage_type::value_type;
    using value_type             = typename storage_type::value_type;
    using size_type              = size_t;
    using difference_type        = ptrdiff_t;
    using key_compare            = Compare;
    using value_compare          = Compare;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using pointer                = typename storage_type::pointer;
    using const_pointer          = typename storage_type::const_pointer;
    using iterator               = typename storage_type::pointer;
    using const_iterator         = typename storage_type::const_pointer;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    /// \brief Constructs empty container.
    constexpr static_set() = default;

    /// \brief Constructs with the contents of the range [first, last). If
    /// multiple elements in the range have keys that compare equivalent, all
    /// but the first will be discarded.
    template <typename InputIt>
        requires(detail::InputIterator<InputIt>)
    constexpr static_set(InputIt first, InputIt last)
    {
        if constexpr (detail::RandomAccessIterator<InputIt>) {
            TETL_ASSERT(last - first >= 0);
            TETL_ASSERT(static_cast<size_type>(last - first) <= max_size());
        }

        insert(first, last);
    }

    /// \brief
    constexpr static_set(static_set const& other) = default;

    /// \brief
    constexpr static_set(static_set&& other) noexcept(noexcept(move(declval<storage_type>()))) = default;

    /// \brief
    constexpr auto operator=(static_set const& other) -> static_set& = default;

    /// \brief
    constexpr auto operator=(static_set&& other) noexcept(noexcept(move(declval<storage_type>())))
        -> static_set& = default;

    /// \brief Returns an iterator to the first element of the set.
    [[nodiscard]] constexpr auto begin() noexcept -> iterator { return _memory.begin(); }

    /// \brief Returns an iterator to the first element of the set.
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator { return _memory.begin(); }

    /// \brief Returns an iterator to the first element of the set.
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator { return begin(); }

    /// \brief Returns an iterator to the element following the last element of
    /// the set.
    [[nodiscard]] constexpr auto end() noexcept -> iterator { return _memory.end(); }

    /// \brief Returns an iterator to the element following the last element of
    /// the set.
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator { return _memory.end(); }

    /// \brief Returns an iterator to the element following the last element of
    /// the set.
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// set. It corresponds to the last element of the non-reversed set.
    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator { return reverse_iterator(end()); }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// set. It corresponds to the last element of the non-reversed set.
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// set. It corresponds to the last element of the non-reversed set.
    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator { return rbegin(); }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed set. It corresponds to the element preceding the
    /// first element of the non-reversed set.
    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator { return reverse_iterator(begin()); }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed set. It corresponds to the element preceding the
    /// first element of the non-reversed set.
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed set. It corresponds to the element preceding the
    /// first element of the non-reversed set.
    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator { return rend(); }

    /// \brief Checks if the container has no elements, i.e. whether begin() ==
    /// end().
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return _memory.empty(); }

    /// \brief Checks if the container full, i.e. whether size() == Capacity.
    [[nodiscard]] constexpr auto full() const noexcept -> bool { return _memory.full(); }

    /// \brief Returns the number of elements in the container, i.e.
    /// distance(begin(), end()).
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return _memory.size(); }

    /// \brief Returns the maximum number of elements the container is able to
    /// hold.
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type { return _memory.max_size(); }

    /// \brief Erases all elements from the container. After this call, size()
    /// returns zero.
    constexpr auto clear() noexcept -> void { _memory.clear(); }

    /// \brief Inserts element into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    constexpr auto insert(value_type&& value) -> pair<iterator, bool>
        requires(is_move_constructible_v<value_type>)
    {
        if (!full()) {
            auto cmp = key_compare {};
            auto* p  = etl::lower_bound(_memory.begin(), _memory.end(), value, cmp);
            if (p == _memory.end() || *(p) != value) {
                _memory.push_back(move(value));
                auto* pos = rotate(p, _memory.end() - 1, _memory.end());
                return make_pair(pos, true);
            }
        }

        return pair<iterator, bool>(nullptr, false);
    }

    /// \brief Inserts element into the container, if the container doesn't
    /// already contain an element with an equivalent key.
    constexpr auto insert(value_type const& value) noexcept(noexcept(insert(move(declval<key_type>()))))
        -> pair<iterator, bool>
        requires(is_copy_constructible_v<value_type>)
    {
        value_type tmp = value;
        return insert(move(tmp));
    }

    /// \brief Inserts elements from range [first, last). If multiple elements
    /// in the range have keys that compare equivalent, it is unspecified which
    /// element is inserted (pending LWG2844).
    template <typename InputIter>
        requires(detail::InputIterator<InputIter>)
    constexpr auto insert(InputIter first, InputIter last) noexcept(noexcept(insert(declval<key_type>()))) -> void
    {
        for (; first != last; ++first) { insert(*first); }
    }

    /// \brief Inserts a new element into the container constructed in-place
    /// with the given args if there is no element with the key in the
    /// container.
    template <typename... Args>
        requires(is_copy_constructible_v<key_type>)
    constexpr auto emplace(Args&&... args) noexcept(noexcept(insert(declval<key_type>()))) -> pair<iterator, bool>
    {
        return insert(value_type(forward<Args>(args)...));
    }

    /// \brief Removes the element at pos.
    ///
    /// https://en.cppreference.com/w/cpp/container/set/erase
    ///
    /// \returns Iterator following the last removed element.
    constexpr auto erase(iterator pos) noexcept -> iterator { return _memory.erase(pos); }

    /// \brief Removes the elements in the range [first; last), which must be a
    /// valid range in *this.
    ///
    /// https://en.cppreference.com/w/cpp/container/set/erase
    ///
    /// \returns Iterator following the last removed element.
    constexpr auto erase(iterator first, iterator last) -> iterator
    {
        auto res = first;
        for (; first != last; ++first) { res = erase(first); }
        return res;
    }

    /// \brief Removes the element (if one exists) with the key equivalent to
    /// key.
    ///
    /// https://en.cppreference.com/w/cpp/container/set/erase
    ///
    /// \returns Number of elements removed.
    constexpr auto erase(key_type const& key) noexcept -> size_type
    {
        if (auto* pos = etl::lower_bound(begin(), end(), key); pos != end()) {
            erase(pos);
            return 1;
        }
        return 0;
    }

    /// \brief Exchanges the contents of the container with those of other.
    constexpr auto swap(static_set& other) noexcept(is_nothrow_swappable_v<key_type>) -> void
        requires(is_assignable_v<key_type&, key_type &&>)
    {
        using etl::move;

        static_set tmp = move(other);
        other          = move(*this);
        (*this)        = move(tmp);
    }

    /// \brief Returns the number of elements with key that compares equivalent
    /// to the specified argument, which is either 1 or 0 since this container
    /// does not allow duplicates.
    [[nodiscard]] constexpr auto count(key_type const& key) const noexcept -> size_type
    {
        return contains(key) ? 1 : 0;
    }

    /// \brief Returns the number of elements with key that compares equivalent
    /// to the value x.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto count(K const& x) const -> size_type
    {
        return contains(x) ? 1 : 0;
    }

    /// \brief Finds an element with key equivalent to key.
    ///
    /// \returns Iterator to an element with key equivalent to key. If no such
    /// element is found, past-the-end (see end()) iterator is returned.
    [[nodiscard]] constexpr auto find(key_type const& key) noexcept -> iterator
    {
        return etl::find(begin(), end(), key);
    }

    /// \brief Finds an element with key equivalent to key.
    ///
    /// \returns Iterator to an element with key equivalent to key. If no such
    /// element is found, past-the-end (see end()) iterator is returned.
    [[nodiscard]] constexpr auto find(key_type const& key) const noexcept -> const_iterator
    {
        return etl::find(begin(), end(), key);
    }

    /// \brief Finds an element with key that compares equivalent to the value
    /// x.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto find(K const& x) -> iterator
    {
        return find_if(begin(), end(), [&x](auto const& val) {
            auto comp = key_compare();
            return comp(val, x);
        });
    }

    /// \brief Finds an element with key that compares equivalent to the value
    /// x.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto find(K const& x) const -> const_iterator
    {
        return find_if(cbegin(), cend(), [&x](auto const& val) {
            auto comp = key_compare();
            return comp(val, x);
        });
    }

    /// \brief Checks if there is an element with key equivalent to key in the
    /// container.
    [[nodiscard]] constexpr auto contains(key_type const& key) const noexcept -> bool { return find(key) != end(); }

    /// \brief Checks if there is an element with key that compares equivalent
    /// to the value x.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto contains(K const& x) const -> bool
    {
        return find(x) != end();
    }

    /// \brief Returns an iterator pointing to the first element that is not
    /// less than (i.e. greater or equal to) key.
    [[nodiscard]] constexpr auto lower_bound(key_type const& key) -> iterator
    {
        return etl::lower_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns an iterator pointing to the first element that is not
    /// less than (i.e. greater or equal to) key.
    [[nodiscard]] constexpr auto lower_bound(key_type const& key) const -> const_iterator
    {
        return etl::lower_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns an iterator pointing to the first element that is not
    /// less than (i.e. greater or equal to) key.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto lower_bound(K const& key) -> iterator
    {
        return etl::lower_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns an iterator pointing to the first element that is not
    /// less than (i.e. greater or equal to) key.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto lower_bound(K const& key) const -> const_iterator
    {
        return etl::lower_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns an iterator pointing to the first element that is greater
    /// than key.
    [[nodiscard]] constexpr auto upper_bound(key_type const& key) -> iterator
    {
        return etl::upper_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns an iterator pointing to the first element that is greater
    /// than key.
    [[nodiscard]] constexpr auto upper_bound(key_type const& key) const -> const_iterator
    {
        return etl::upper_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns an iterator pointing to the first element that is greater
    /// than key.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto upper_bound(K const& key) -> iterator
    {
        return etl::upper_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns an iterator pointing to the first element that is greater
    /// than key.
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto upper_bound(K const& key) const -> const_iterator
    {
        return etl::upper_bound(begin(), end(), key, key_compare {});
    }

    /// \brief Returns a range containing all elements with the given key in the
    /// container. The range is defined by two iterators, one pointing to the
    /// first element that is not less than key and another pointing to the
    /// first element greater than key. Alternatively, the first iterator may be
    /// obtained with lower_bound(), and the second with upper_bound().
    [[nodiscard]] constexpr auto equal_range(key_type const& key) -> iterator
    {
        return etl::equal_range(begin(), end(), key, key_compare {});
    }

    /// \brief Returns a range containing all elements with the given key in the
    /// container. The range is defined by two iterators, one pointing to the
    /// first element that is not less than key and another pointing to the
    /// first element greater than key. Alternatively, the first iterator may be
    /// obtained with lower_bound(), and the second with upper_bound().
    [[nodiscard]] constexpr auto equal_range(key_type const& key) const -> const_iterator
    {
        return etl::equal_range(begin(), end(), key, key_compare {});
    }

    /// \brief Returns a range containing all elements with the given key in the
    /// container. The range is defined by two iterators, one pointing to the
    /// first element that is not less than key and another pointing to the
    /// first element greater than key. Alternatively, the first iterator may be
    /// obtained with lower_bound(), and the second with upper_bound().
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto equal_range(K const& key) -> iterator
    {
        return etl::equal_range(begin(), end(), key, key_compare {});
    }

    /// \brief Returns a range containing all elements with the given key in the
    /// container. The range is defined by two iterators, one pointing to the
    /// first element that is not less than key and another pointing to the
    /// first element greater than key. Alternatively, the first iterator may be
    /// obtained with lower_bound(), and the second with upper_bound().
    template <typename K>
        requires(detail::is_transparent_v<key_compare>)
    [[nodiscard]] constexpr auto equal_range(K const& key) const -> const_iterator
    {
        return etl::equal_range(begin(), end(), key, key_compare {});
    }

    /// \brief Returns the function object that compares the keys, which is a
    /// copy of this container's constructor argument comp. It is the same as
    /// value_comp.
    ///
    /// \returns The key comparison function object.
    [[nodiscard]] auto key_comp() const noexcept -> key_compare { return key_compare(); }

    /// \brief Returns the function object that compares the values. It is the
    /// same as key_comp.
    ///
    /// \returns The value comparison function object.
    [[nodiscard]] auto value_comp() const noexcept -> value_compare { return value_compare(); }
};

/// \brief Compares the contents of two sets.
///
/// \details Checks if the contents of lhs and rhs are equal, that is, they have
/// the same number of elements and each element in lhs compares equal with the
/// element in rhs at the same position.
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto operator==(
    static_set<Key, Capacity, Comp> const& lhs, static_set<Key, Capacity, Comp> const& rhs) -> bool
{
    return lhs.size() == rhs.size() && equal(begin(lhs), end(lhs), begin(rhs));
}

/// \brief Compares the contents of two sets.
///
/// \details Checks if the contents of lhs and rhs are equal, that is, they have
/// the same number of elements and each element in lhs compares equal with the
/// element in rhs at the same position.
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto operator!=(
    static_set<Key, Capacity, Comp> const& lhs, static_set<Key, Capacity, Comp> const& rhs) -> bool
{
    return !(lhs == rhs);
}

/// \brief Compares the contents of two sets.
///
/// \details Compares the contents of lhs and rhs lexicographically. The
/// comparison is performed by a function equivalent to
/// lexicographical_compare. This comparison ignores the set's ordering
/// Compare.
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto operator<(
    static_set<Key, Capacity, Comp> const& lhs, static_set<Key, Capacity, Comp> const& rhs) -> bool
{
    return lexicographical_compare(begin(lhs), end(lhs), begin(rhs), end(rhs));
}

/// \brief Compares the contents of two sets.
///
/// \details Compares the contents of lhs and rhs lexicographically. The
/// comparison is performed by a function equivalent to
/// lexicographical_compare. This comparison ignores the set's ordering
/// Compare.
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto operator<=(
    static_set<Key, Capacity, Comp> const& lhs, static_set<Key, Capacity, Comp> const& rhs) -> bool
{
    return !(rhs < lhs);
}

/// \brief Compares the contents of two sets.
///
/// \details Compares the contents of lhs and rhs lexicographically. The
/// comparison is performed by a function equivalent to
/// lexicographical_compare. This comparison ignores the set's ordering
/// Compare.
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto operator>(
    static_set<Key, Capacity, Comp> const& lhs, static_set<Key, Capacity, Comp> const& rhs) -> bool
{
    return rhs < lhs;
}

/// \brief Compares the contents of two sets.
///
/// \details Compares the contents of lhs and rhs lexicographically. The
/// comparison is performed by a function equivalent to
/// lexicographical_compare. This comparison ignores the set's ordering
/// Compare.
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto operator>=(
    static_set<Key, Capacity, Comp> const& lhs, static_set<Key, Capacity, Comp> const& rhs) -> bool
{
    return !(lhs < rhs);
}

/// \brief Specializes the swap algorithm for set. Swaps the contents
/// of lhs and rhs. Calls lhs.swap(rhs).
template <typename Key, size_t Capacity, typename Compare>
constexpr auto swap(static_set<Key, Capacity, Compare>& lhs, static_set<Key, Capacity, Compare>& rhs) noexcept(
    noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

// /// \brief Erases all elements that satisfy the predicate pred from the
// container.
// ///
// /// https://en.cppreference.com/w/cpp/container/set/erase_if
// template <typename Key, size_t Capacity, typename Compare, typename
// Predicate> constexpr auto erase_if(static_set<Key, Capacity, Compare>&
// c, Predicate pred) ->
//     typename static_set<Key, Capacity, Compare>::size_type
// {
//     auto const old_size = c.size();
//     for (auto i = c.begin(), last = c.end(); i != last;)
//     {
//         if (pred(*i)) { i = c.erase(i); }
//         else
//         {
//             ++i;
//         }
//     }

//     return old_size - c.size();
// }

} // namespace etl

#endif // TETL_SET_STATIC_SET_HPP

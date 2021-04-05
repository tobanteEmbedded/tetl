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
 * @file set.hpp
 * @example set.cpp
 */

#ifndef TAETL_SET_HPP
#define TAETL_SET_HPP

#include "etl/algorithm.hpp"   // for lower_bound, rotate
#include "etl/array.hpp"       // for array
#include "etl/functional.hpp"  // for less
#include "etl/iterator.hpp"    // for reverse_iterator
#include "etl/utility.hpp"     // for forward

#include "etl/detail/container_utils.hpp"

namespace etl
{
namespace detail
{
/**
 * @brief Storage for zero elements.
 */
template <typename Key>
class static_set_zero_storage
{
  public:
  using value_type      = Key;
  using key_type        = Key;
  using size_type       = uint8_t;
  using difference_type = ptrdiff_t;
  using pointer         = Key*;
  using const_pointer   = Key const*;
  using iterator        = Key*;
  using const_iterator  = Key const*;

  /**
   * @brief Defaulted constructor.
   */
  constexpr static_set_zero_storage() = default;

  /**
   * @brief Defaulted copy constructor.
   */
  constexpr static_set_zero_storage(static_set_zero_storage const&) = default;

  /**
   * @brief Defaulted copy assignment .
   */
  constexpr auto operator       =(static_set_zero_storage const&) noexcept
    -> static_set_zero_storage& = default;

  /**
   * @brief Defaulted move constructor.
   */
  constexpr static_set_zero_storage(
    static_set_zero_storage&&) noexcept = default;

  /**
   * @brief Defaulted move assignment.
   */
  constexpr auto operator       =(static_set_zero_storage&&) noexcept
    -> static_set_zero_storage& = default;

  /**
   * @brief Defaulted destructor.
   */
  ~static_set_zero_storage() = default;

  /**
   * @brief Returns an iterator to the first element of the set.
   */
  [[nodiscard]] constexpr auto begin() noexcept -> iterator { return nullptr; }

  /**
   * @brief Returns an iterator to the first element of the set.
   */
  [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
  {
    return nullptr;
  }

  /**
   * @brief Returns an iterator to the element following the last element of the
   * set.
   */
  [[nodiscard]] constexpr auto end() noexcept -> iterator { return nullptr; }

  /**
   * @brief Returns an iterator to the element following the last element of the
   * set.
   */
  [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
  {
    return nullptr;
  }

  /**
   * @brief Number of elements currently stored.
   */
  [[nodiscard]] static constexpr auto size() noexcept -> size_type { return 0; }

  /**
   * @brief Capacity of the storage.
   */
  [[nodiscard]] static constexpr auto max_size() noexcept -> size_type
  {
    return 0;
  }

  /**
   * @brief Is the storage empty?
   */
  [[nodiscard]] static constexpr auto empty() noexcept -> bool { return true; }

  /**
   * @brief Is the storage full?
   */
  [[nodiscard]] static constexpr auto full() noexcept -> bool { return true; }

  /**
   * @brief
   */
  static constexpr auto insert(value_type&& /*value*/) -> pair<iterator, bool>
  {
    assert(false && "tried to insert on empty storage");
    return pair<iterator, bool> {nullptr, false};
  }

  protected:
  /**
   * @brief (unsafe) Changes the container size to new_size.
   *
   * @warning No elements are constructed or destroyed.
   */
  constexpr void unsafe_set_size([[maybe_unused]] size_t newSize) noexcept
  {
    assert(newSize == 0 && "new_size out-of-bounds for empty storage");
  }

  /**
   * @brief Destroys all elements of the storage in range [begin, end) without
   * changings its size (unsafe). Nothing to destroy since the storage is empty.
   */
  template <typename InputIt>
  static constexpr auto unsafe_destroy(InputIt /* begin */,
                                       InputIt /* end */) noexcept -> void
  {
  }

  /**
   * @brief Destroys all elements of the storage without changing its size
   * (unsafe). Nothing to destroy since the storage is empty.
   */
  static constexpr void unsafe_destroy_all() noexcept { }
};

/**
 * @brief Storage for trivial types.
 */
template <typename Key, size_t Capacity, typename Compare>
class static_set_trivial_storage
{
  static_assert(is_trivial_v<Key>);
  static_assert(Capacity != size_t());

  public:
  using value_type      = Key;
  using key_type        = Key;
  using size_type       = smallest_size_t<Capacity>;
  using difference_type = ptrdiff_t;
  using pointer         = Key*;
  using const_pointer   = Key const*;
  using iterator        = Key*;
  using const_iterator  = Key const*;
  using key_compare     = Compare;
  using value_compare   = Compare;

  /**
   * @brief Default ctor.
   */
  constexpr static_set_trivial_storage() noexcept = default;

  /**
   * @brief Default copy.
   */
  constexpr static_set_trivial_storage(
    static_set_trivial_storage const&) noexcept = default;

  /**
   * @brief Default copy assignment.
   */
  constexpr auto operator          =(static_set_trivial_storage const&) noexcept
    -> static_set_trivial_storage& = default;

  /**
   * @brief Default move.
   */
  constexpr static_set_trivial_storage(
    static_set_trivial_storage&&) noexcept = default;

  /**
   * @brief Default move assignment.
   */
  constexpr auto operator          =(static_set_trivial_storage&&) noexcept
    -> static_set_trivial_storage& = default;

  /**
   * @brief Default dtor.
   */
  ~static_set_trivial_storage() = default;

  /**
   * @brief Returns an iterator to the first element of the set.
   */
  [[nodiscard]] constexpr auto begin() noexcept -> iterator
  {
    return data_.data();
  }

  /**
   * @brief Returns an iterator to the first element of the set.
   */
  [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
  {
    return data_.data();
  }

  /**
   * @brief Returns an iterator to the element following the last element of the
   * set.
   */
  [[nodiscard]] constexpr auto end() noexcept -> iterator
  {
    return data_.data() + size_;
  }

  /**
   * @brief Returns an iterator to the element following the last element of the
   * set.
   */
  [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
  {
    return data_.data() + size_;
  }

  /**
   * @brief Number of elements in the storage.
   */
  [[nodiscard]] constexpr auto size() const noexcept -> size_type
  {
    return size_;
  }

  /**
   * @brief Maximum number of elements that can be allocated in the storage.
   */
  [[nodiscard]] constexpr auto max_size() noexcept -> size_type
  {
    return Capacity;
  }

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
   * @brief
   */
  constexpr auto insert(value_type&& value)
    -> enable_if_t<is_move_constructible_v<value_type>, pair<iterator, bool>>
  {
    if (!full())
    {
      auto* p = lower_bound(begin(), end(), value, key_compare {});
      if (p == end() || *(p) != value)
      {
        data_[size_++] = move(value);
        auto* pos      = rotate(p, end() - 1, end());
        return make_pair(pos, true);
      }
    }

    return pair<iterator, bool>(nullptr, false);
  }

  protected:
  /**
   * @brief (unsafe) Changes the container size to new_size.
   *
   * @warning No elements are constructed or destroyed.
   */
  constexpr void unsafe_set_size(size_t newSize) noexcept
  {
    assert(newSize <= Capacity && "new_size out-of-bounds [0, Capacity)");
    size_ = size_type(newSize);
  }

  /**
   * @brief (unsafe) Destroy elements in the range [begin, end).
   *
   * @warning The size of the storage is not changed.
   */
  template <typename InputIt>
  constexpr auto unsafe_destroy(InputIt /*unused*/, InputIt /*unused*/) noexcept
    -> void
  {
  }

  /**
   * @brief (unsafe) Destroys all elements of the storage.
   *
   * @warning The size of the storage is not changed.
   */
  constexpr auto unsafe_destroy_all() noexcept -> void { }

  private:
  // If the value_type is const, make a const array of non-const elements:
  static constexpr auto condition = !is_const_v<Key>;
  using mutable_storage_t         = array<Key, Capacity>;
  using const_storage_t           = array<remove_const_t<Key>, Capacity> const;
  using storage_t
    = conditional_t<condition, mutable_storage_t, const_storage_t>;

  alignas(alignof(Key)) storage_t data_ {};
  size_type size_ = 0;
};

/**
 * @brief Selects the vector storage.
 */
template <typename Key, size_t Capacity, typename Compare = less<Key>>
using static_set_storage_type
  = conditional_t<Capacity == 0, static_set_zero_storage<Key>,
                  static_set_trivial_storage<Key, Capacity, Compare>>;
}  // namespace detail

/**
 * @brief static_set is an associative container that contains a sorted set
 * of unique objects of type Key. Sorting is done using the key comparison
 * function Compare.
 *
 * @include set.cpp
 */
template <typename Key, size_t Capacity, typename Compare = less<Key>>
class static_set
    : private detail::static_set_storage_type<Key, Capacity, Compare>
{
  private:
  static_assert(is_nothrow_destructible_v<Key>);
  using base_type = detail::static_set_storage_type<Key, Capacity>;
  using self      = static_set<Key, Capacity>;

  using base_type::unsafe_destroy;
  using base_type::unsafe_destroy_all;
  using base_type::unsafe_set_size;

  public:
  using key_type               = typename base_type::key_type;
  using value_type             = typename base_type::value_type;
  using size_type              = size_t;
  using difference_type        = ptrdiff_t;
  using key_compare            = Compare;
  using value_compare          = Compare;
  using reference              = value_type&;
  using const_reference        = value_type const&;
  using pointer                = typename base_type::pointer;
  using const_pointer          = typename base_type::const_pointer;
  using iterator               = typename base_type::pointer;
  using const_iterator         = typename base_type::const_pointer;
  using reverse_iterator       = etl::reverse_iterator<iterator>;
  using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

  /**
   * @brief Default constructor. Constructs empty container.
   */
  static_set() = default;

  /**
   * @brief Constructs the container with the contents of the range [first,
   * last).
   *
   * @details If multiple elements in the range have keys that compare
   * equivalent, it is unspecified which element is inserted (pending LWG2844).
   */
  template <typename InputIter,
            TAETL_REQUIRES_(detail::InputIterator<InputIter>)>
  static_set(InputIter first, InputIter last) noexcept(
    noexcept(base_type::insert(declval<key_type>())))
  {
    if constexpr (detail::RandomAccessIterator<InputIter>)
    {
      assert(last - first >= 0);
      assert(static_cast<size_type>(last - first) <= max_size());
    }

    insert(first, last);
  }

  /**
   * @brief Returns an iterator to the first element of the set.
   */
  using base_type::begin;

  /**
   * @brief Returns an iterator to the first element of the set.
   */
  [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
  {
    return begin();
  }

  /**
   * @brief Returns an iterator to the element following the last element of the
   * set.
   */
  using base_type::end;

  /**
   * @brief Returns an iterator to the element following the last element of the
   * set.
   */
  [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
  {
    return end();
  }

  /**
   * @brief Returns a reverse iterator to the first element of the reversed set.
   * It corresponds to the last element of the non-reversed set.
   */
  [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
  {
    return reverse_iterator(end());
  }

  /**
   * @brief Returns a reverse iterator to the first element of the reversed set.
   * It corresponds to the last element of the non-reversed set.
   */
  [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
  {
    return const_reverse_iterator(end());
  }

  /**
   * @brief Returns a reverse iterator to the first element of the reversed set.
   * It corresponds to the last element of the non-reversed set.
   */
  [[nodiscard]] constexpr auto crbegin() const noexcept
    -> const_reverse_iterator
  {
    return rbegin();
  }

  /**
   * @brief Returns a reverse iterator to the element following the last element
   * of the reversed set. It corresponds to the element preceding the first
   * element of the non-reversed set.
   */
  [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
  {
    return reverse_iterator(begin());
  }

  /**
   * @brief Returns a reverse iterator to the element following the last element
   * of the reversed set. It corresponds to the element preceding the first
   * element of the non-reversed set.
   */
  [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
  {
    return const_reverse_iterator(begin());
  }

  /**
   * @brief Returns a reverse iterator to the element following the last element
   * of the reversed set. It corresponds to the element preceding the first
   * element of the non-reversed set.
   */
  [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator
  {
    return rend();
  }

  /**
   * @brief Checks if the container has no elements, i.e. whether begin() ==
   * end().
   */
  using base_type::empty;

  /**
   * @brief Checks if the container full, i.e. whether size() == Capacity.
   */
  using base_type::full;

  /**
   * @brief Returns the number of elements in the container, i.e.
   * distance(begin(), end()).
   */
  using base_type::size;

  /**
   * @brief Returns the maximum number of elements the container is able to
   * hold.
   */
  using base_type::max_size;

  /**
   * @brief Erases all elements from the container. After this call, size()
   * returns zero.
   */
  constexpr auto clear() noexcept -> void
  {
    unsafe_destroy_all();
    unsafe_set_size(0);
  }

  /**
   * @brief Inserts element into the container, if the container doesn't
   * already contain an element with an equivalent key.
   */
  using base_type::insert;

  /**
   * @brief Inserts element into the container, if the container doesn't
   * already contain an element with an equivalent key.
   *
   * @todo noexcept(noexcept(base_type::insert(move(declval<key_type>()))))
   * breaks GCC 9.3 Ubuntu Focal build
   */
  auto insert(value_type const& value)
    -> enable_if_t<is_copy_constructible_v<value_type>, pair<iterator, bool>>
  {
    value_type tmp = value;
    return insert(move(tmp));
  }

  /**
   * @brief Inserts elements from range [first, last). If multiple elements in
   * the range have keys that compare equivalent, it is unspecified which
   * element is inserted (pending LWG2844).
   */
  template <typename InputIter,
            TAETL_REQUIRES_(detail::InputIterator<InputIter>)>
  auto insert(InputIter first,
              InputIter last) noexcept(noexcept(insert(declval<key_type>())))
    -> void
  {
    for (; first != last; ++first) { insert(*first); }
  }

  /**
   * @brief Inserts a new element into the container constructed in-place with
   * the given args if there is no element with the key in the container.
   */
  template <typename... Args,
            TAETL_REQUIRES_(is_copy_constructible_v<key_type>)>
  auto emplace(Args&&... args) noexcept(noexcept(insert(declval<key_type>())))
    -> pair<iterator, bool>
  {
    return insert(value_type(forward<Args>(args)...));
  }

  /**
   * @brief Removes the element at pos.
   *
   * https://en.cppreference.com/w/cpp/container/set/erase
   *
   * @return Iterator following the last removed element.
   */
  constexpr auto erase(iterator pos) noexcept -> iterator
  {
    rotate(pos, pos + 1, end());
    unsafe_set_size(static_cast<size_type>(size() - 1));
    return pos + 1;
  }

  /**
   * @brief Removes the elements in the range [first; last), which must be a
   * valid range in *this.
   *
   * https://en.cppreference.com/w/cpp/container/set/erase
   *
   * @return Iterator following the last removed element.
   */
  constexpr auto erase(iterator first, iterator last) -> iterator
  {
    auto res = first;
    for (; first != last; ++first) { res = erase(first); }
    return res;
  }

  /**
   * @brief Removes the element (if one exists) with the key equivalent to key.
   *
   * https://en.cppreference.com/w/cpp/container/set/erase
   *
   * @return Number of elements removed.
   */
  constexpr auto erase(key_type const& key) noexcept -> size_type
  {
    if (auto* pos = ::etl::lower_bound(begin(), end(), key); pos != end())
    {
      erase(pos);
      return 1;
    }
    return 0;
  }

  /**
   * @brief Exchanges the contents of the container with those of other.
   */
  constexpr auto
  swap(static_set& other) noexcept(is_nothrow_swappable_v<key_type>)
    -> enable_if_t<is_assignable_v<key_type&, key_type&&>, void>
  {
    using ::etl::move;

    static_set tmp = move(other);
    other          = move(*this);
    (*this)        = move(tmp);
  }

  /**
   * @brief Returns the number of elements with key that compares equivalent to
   * the specified argument, which is either 1 or 0 since this container does
   * not allow duplicates.
   */
  [[nodiscard]] constexpr auto count(key_type const& key) const noexcept
    -> size_type
  {
    return contains(key) ? 1 : 0;
  }

  /**
   * @brief Returns the number of elements with key that compares equivalent to
   * the value x.
   */
  template <typename K,
            TAETL_REQUIRES_(detail::is_transparent<key_compare, K>::value)>
  [[nodiscard]] constexpr auto count(K const& x) const -> size_type
  {
    return contains(x) ? 1 : 0;
  }

  /**
   * @brief Finds an element with key equivalent to key.
   *
   * @return Iterator to an element with key equivalent to key. If no such
   * element is found, past-the-end (see end()) iterator is returned.
   */
  [[nodiscard]] constexpr auto find(key_type const& key) noexcept -> iterator
  {
    return ::etl::find(begin(), end(), key);
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
    return ::etl::find(begin(), end(), key);
  }

  /**
   * @brief Finds an element with key that compares equivalent to the value x.
   */
  template <typename K,
            TAETL_REQUIRES_(detail::is_transparent<key_compare, K>::value)>
  constexpr auto find(K const& x) -> iterator
  {
    return find_if(begin(), end(),
                   [&x](auto const& val)
                   {
                     auto comp = key_compare();
                     return comp(val, x);
                   });
  }

  /**
   * @brief Finds an element with key that compares equivalent to the value x.
   */
  template <typename K,
            TAETL_REQUIRES_(detail::is_transparent<key_compare, K>::value)>
  constexpr auto find(K const& x) const -> const_iterator
  {
    return find_if(cbegin(), cend(),
                   [&x](auto const& val)
                   {
                     auto comp = key_compare();
                     return comp(val, x);
                   });
  }

  /**
   * @brief Checks if there is an element with key equivalent to key in the
   * container.
   */
  [[nodiscard]] constexpr auto contains(key_type const& key) const noexcept
    -> bool
  {
    return find(key) != end();
  }

  /**
   * @brief Checks if there is an element with key that compares equivalent to
   the value
   * x.
   */
  template <typename K,
            TAETL_REQUIRES_(detail::is_transparent<key_compare, K>::value)>
  [[nodiscard]] constexpr auto contains(K const& x) const -> bool
  {
    return find(x) != end();
  }

  /**
   * @brief Returns an iterator pointing to the first element that is not less
   * than (i.e. greater or equal to) key.
   */
  [[nodiscard]] constexpr auto lower_bound(key_type const& key) -> iterator
  {
    return ::etl::lower_bound(begin(), end(), key, key_compare {});
  }

  /**
   * @brief Returns an iterator pointing to the first element that is not less
   * than (i.e. greater or equal to) key.
   */
  [[nodiscard]] constexpr auto lower_bound(key_type const& key) const
    -> const_iterator
  {
    return ::etl::lower_bound(begin(), end(), key, key_compare {});
  }

  /**
   * @brief Returns an iterator pointing to the first element that is greater
   than key.
   */
  [[nodiscard]] constexpr auto upper_bound(key_type const& key) -> iterator
  {
    return ::etl::upper_bound(begin(), end(), key, key_compare {});
  }

  /**
   * @brief Returns an iterator pointing to the first element that is greater
   than key.
   */
  [[nodiscard]] constexpr auto upper_bound(key_type const& key) const
    -> const_iterator
  {
    return ::etl::upper_bound(begin(), end(), key, key_compare {});
  }

  /**
   * @brief Returns a range containing all elements with the given key in the
   * container. The range is defined by two iterators, one pointing to the first
   * element that is not less than key and another pointing to the first element
   * greater than key. Alternatively, the first iterator may be obtained with
   * lower_bound(), and the second with upper_bound().
   */
  [[nodiscard]] constexpr auto equal_range(key_type const& key) -> iterator
  {
    return ::etl::equal_range(begin(), end(), key, key_compare {});
  }

  /**
   * @brief Returns a range containing all elements with the given key in the
   * container. The range is defined by two iterators, one pointing to the first
   * element that is not less than key and another pointing to the first element
   * greater than key. Alternatively, the first iterator may be obtained with
   * lower_bound(), and the second with upper_bound().
   */
  [[nodiscard]] constexpr auto equal_range(key_type const& key) const
    -> const_iterator
  {
    return ::etl::equal_range(begin(), end(), key, key_compare {});
  }
  /**
   * @brief Returns the function object that compares the keys, which is a copy
   * of this container's constructor argument comp. It is the same as
   * value_comp.
   *
   * @return The key comparison function object.
   */
  [[nodiscard]] auto key_comp() const noexcept -> key_compare
  {
    return key_compare();
  }

  /**
   * @brief Returns the function object that compares the values. It is the same
   * as key_comp.
   *
   * @return The value comparison function object.
   */
  [[nodiscard]] auto value_comp() const noexcept -> value_compare
  {
    return value_compare();
  }
};

/**
 * @brief Compares the contents of two sets.
 *
 * @details Checks if the contents of lhs and rhs are equal, that is, they have
 * the same number of elements and each element in lhs compares equal with the
 * element in rhs at the same position.
 */
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto
operator==(static_set<Key, Capacity, Comp> const& lhs,
           static_set<Key, Capacity, Comp> const& rhs) -> bool
{
  return lhs.size() == rhs.size() && equal(begin(lhs), end(lhs), begin(rhs));
}

/**
 * @brief Compares the contents of two sets.
 *
 * @details Checks if the contents of lhs and rhs are equal, that is, they have
 * the same number of elements and each element in lhs compares equal with the
 * element in rhs at the same position.
 */
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto
operator!=(static_set<Key, Capacity, Comp> const& lhs,
           static_set<Key, Capacity, Comp> const& rhs) -> bool
{
  return !(lhs == rhs);
}

/**
 * @brief Compares the contents of two sets.
 *
 * @details Compares the contents of lhs and rhs lexicographically. The
 * comparison is performed by a function equivalent to
 * lexicographical_compare. This comparison ignores the set's ordering
 * Compare.
 */
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto
operator<(static_set<Key, Capacity, Comp> const& lhs,
          static_set<Key, Capacity, Comp> const& rhs) -> bool
{
  return lexicographical_compare(begin(lhs), end(lhs), begin(rhs), end(rhs));
}

/**
 * @brief Compares the contents of two sets.
 *
 * @details Compares the contents of lhs and rhs lexicographically. The
 * comparison is performed by a function equivalent to
 * lexicographical_compare. This comparison ignores the set's ordering
 * Compare.
 */
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto
operator<=(static_set<Key, Capacity, Comp> const& lhs,
           static_set<Key, Capacity, Comp> const& rhs) -> bool
{
  return !(rhs < lhs);
}

/**
 * @brief Compares the contents of two sets.
 *
 * @details Compares the contents of lhs and rhs lexicographically. The
 * comparison is performed by a function equivalent to
 * lexicographical_compare. This comparison ignores the set's ordering
 * Compare.
 */
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto
operator>(static_set<Key, Capacity, Comp> const& lhs,
          static_set<Key, Capacity, Comp> const& rhs) -> bool
{
  return rhs < lhs;
}

/**
 * @brief Compares the contents of two sets.
 *
 * @details Compares the contents of lhs and rhs lexicographically. The
 * comparison is performed by a function equivalent to
 * lexicographical_compare. This comparison ignores the set's ordering
 * Compare.
 */
template <typename Key, size_t Capacity, typename Comp>
[[nodiscard]] constexpr auto
operator>=(static_set<Key, Capacity, Comp> const& lhs,
           static_set<Key, Capacity, Comp> const& rhs) -> bool
{
  return !(lhs < rhs);
}

/**
 * @brief Specializes the swap algorithm for set. Swaps the contents
 * of lhs and rhs. Calls lhs.swap(rhs).
 */
template <typename Key, size_t Capacity, typename Compare>
constexpr auto
swap(static_set<Key, Capacity, Compare>& lhs,
     static_set<Key, Capacity, Compare>& rhs) noexcept(noexcept(lhs.swap(rhs)))
  -> void
{
  lhs.swap(rhs);
}

// /**
//  * @brief Erases all elements that satisfy the predicate pred from the
//  container.
//  *
//  * https://en.cppreference.com/w/cpp/container/set/erase_if
//  */
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

}  // namespace etl

#endif  // TAETL_SET_HPP
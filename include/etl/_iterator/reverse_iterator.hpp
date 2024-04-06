// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_REVERSE_ITERATOR_HPP
#define TETL_ITERATOR_REVERSE_ITERATOR_HPP

#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_memory/addressof.hpp>

namespace etl {

/// reverse_iterator is an iterator adaptor that reverses the direction
/// of a given iterator. In other words, when provided with a bidirectional
/// iterator, `reverse_iterator` produces a new iterator that moves from the end
/// to the beginning of the sequence defined by the underlying bidirectional
/// iterator. This is the iterator returned by member functions `rbegin()` and
/// `rend()` of the standard library containers.
///
/// https://en.cppreference.com/w/cpp/iterator/reverse_iterator
///
/// \ingroup iterator
template <typename Iter>
struct reverse_iterator {
    using iterator_type     = Iter;
    using value_type        = typename iterator_traits<Iter>::value_type;
    using difference_type   = typename etl::iterator_traits<Iter>::difference_type;
    using reference         = typename etl::iterator_traits<Iter>::reference;
    using pointer           = typename etl::iterator_traits<Iter>::pointer;
    using iterator_category = typename etl::iterator_traits<Iter>::iterator_category;

    /// Constructs a new iterator adaptor.
    ///
    /// Default constructor. The underlying iterator is
    /// value-initialized. Operations on the resulting iterator have defined
    /// behavior if and only if the corresponding operations on a
    /// value-initialized Iterator also have defined behavior.
    constexpr reverse_iterator()
        : _current()
    {
    }

    /// Constructs a new iterator adaptor.
    ///
    /// The underlying iterator is initialized with x.
    constexpr explicit reverse_iterator(Iter x)
        : _current(x)
    {
    }

    /// Constructs a new iterator adaptor.
    ///
    /// The underlying iterator is initialized with that of other.
    template <typename Other>
    constexpr reverse_iterator(reverse_iterator<Other> const& other)
        : _current(other.base())
    {
    }

    /// The underlying iterator is assigned the value of the underlying
    /// iterator of other, i.e. other.base().
    template <typename Other>
    constexpr auto operator=(reverse_iterator<Other> const& other) -> reverse_iterator&
    {
        _current = other.base();
        return *this;
    }

    /// Returns the underlying base iterator.
    [[nodiscard]] constexpr auto base() const -> Iter { return _current; }

    /// Returns a reference to the element previous to current.
    constexpr auto operator*() const -> reference
    {
        auto tmp = _current;
        return *--tmp;
    }

    /// Returns a pointer to the element previous to current.
    constexpr auto operator->() const -> pointer { return etl::addressof(operator*()); }

    /// Pre-increments by one respectively.
    constexpr auto operator++() -> reverse_iterator&
    {
        --_current;
        return *this;
    }

    /// Pre-increments by one respectively.
    constexpr auto operator++(int) -> reverse_iterator
    {
        auto tmp(*this);
        --_current;
        return tmp;
    }

    /// Pre-decrements by one respectively.
    constexpr auto operator--() -> reverse_iterator&
    {
        ++_current;
        return *this;
    }

    /// Pre-decrements by one respectively.
    constexpr auto operator--(int) -> reverse_iterator
    {
        auto tmp(*this);
        ++_current;
        return tmp;
    }

    /// Returns an iterator which is advanced by n positions.
    constexpr auto operator+(difference_type n) const -> reverse_iterator { return reverse_iterator(_current - n); }

    /// Advances the iterator by n or -n positions respectively.
    constexpr auto operator+=(difference_type n) -> reverse_iterator&
    {
        _current -= n;
        return *this;
    }

    /// Returns an iterator which is advanced by -n positions.
    constexpr auto operator-(difference_type n) const -> reverse_iterator { return reverse_iterator(_current + n); }

    /// Advances the iterator by n or -n positions respectively.
    constexpr auto operator-=(difference_type n) -> reverse_iterator&
    {
        _current += n;
        return *this;
    }

    /// Returns a reference to the element at specified relative location.
    constexpr auto operator[](difference_type n) const -> reference { return *(*this + n); }

private:
    Iter _current;
};

/// Convenience function template that constructs a etl::reverse_iterator
/// for the given iterator i (which must be a LegacyBidirectionalIterator) with
/// the type deduced from the type of the argument.
template <typename Iter>
[[nodiscard]] constexpr auto make_reverse_iterator(Iter i) noexcept -> etl::reverse_iterator<Iter>
{
    return etl::reverse_iterator<Iter>(i);
}

/// Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto
operator==(etl::reverse_iterator<Iter1> const& lhs, etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() == rhs.base();
}

/// Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto
operator!=(etl::reverse_iterator<Iter1> const& lhs, etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() != rhs.base();
}

/// Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto
operator<(etl::reverse_iterator<Iter1> const& lhs, etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() < rhs.base();
}

/// Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto
operator<=(etl::reverse_iterator<Iter1> const& lhs, etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() <= rhs.base();
}

/// Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto
operator>(etl::reverse_iterator<Iter1> const& lhs, etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() > rhs.base();
}

/// Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto
operator>=(etl::reverse_iterator<Iter1> const& lhs, etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() >= rhs.base();
}

/// Returns the iterator it incremented by n.
template <typename Iter>
[[nodiscard]] constexpr auto operator+(
    typename reverse_iterator<Iter>::difference_type n,
    reverse_iterator<Iter> const& it
) noexcept(noexcept(it.base() - n)) -> reverse_iterator<Iter>
{
    return reverse_iterator<Iter>(it.base() - n);
}

/// Returns the distance between two iterator adaptors.
template <typename Iterator1, typename Iterator2>
constexpr auto operator-(reverse_iterator<Iterator1> const& lhs, reverse_iterator<Iterator2> const& rhs) noexcept(
    noexcept(rhs.base() - lhs.base())
) -> decltype(rhs.base() - lhs.base())
{
    return rhs.base() - lhs.base();
}

} // namespace etl

#endif // TETL_ITERATOR_REVERSE_ITERATOR_HPP

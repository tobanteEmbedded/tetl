// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP
#define TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP

#include <etl/iterator.hpp>

template <typename It>
struct InIter {
    using iterator_category = etl::input_iterator_tag;
    using value_type        = typename etl::iterator_traits<It>::value_type;
    using difference_type   = typename etl::iterator_traits<It>::difference_type;
    using pointer           = It;
    using reference         = typename etl::iterator_traits<It>::reference;

    [[nodiscard]] constexpr auto base() const -> It { return _iter; }

    constexpr InIter() : _iter() { }

    explicit constexpr InIter(It it) : _iter(it) { }

    template <typename U>
    constexpr InIter(InIter<U> const& u) : _iter(u.iter_)
    {
    }

    constexpr auto operator*() const -> reference { return *_iter; }

    constexpr auto operator->() const -> pointer { return _iter; }

    constexpr auto operator++() -> InIter&
    {
        ++_iter;
        return *this;
    }

    constexpr auto operator++(int) -> InIter
    {
        InIter tmp(*this);
        ++(*this);
        return tmp;
    }

private:
    It _iter;

    template <typename U>
    friend struct InIter;
};

template <typename T, typename U>
constexpr auto operator==(InIter<T> const& x, InIter<U> const& y) -> bool
{
    return x.base() == y.base();
}

template <typename T, typename U>
constexpr auto operator!=(InIter<T> const& x, InIter<U> const& y) -> bool
{
    return !(x == y);
}

template <typename Iter>
struct FwdIter {
    using iterator_category = etl::forward_iterator_tag;
    using value_type        = typename etl::iterator_traits<Iter>::value_type;
    using difference_type   = typename etl::iterator_traits<Iter>::difference_type;
    using pointer           = Iter;
    using reference         = typename etl::iterator_traits<Iter>::reference;

    [[nodiscard]] constexpr auto base() const -> Iter { return _iter; }

    constexpr FwdIter() = default;

    explicit constexpr FwdIter(Iter it) : _iter{it} { }

    template <typename U>
    constexpr FwdIter(FwdIter<U> const& u) : _iter(u.iter_)
    {
    }

    [[nodiscard]] constexpr auto operator*() const -> reference { return *_iter; }

    [[nodiscard]] constexpr auto operator->() const -> pointer { return _iter; }

    constexpr auto operator++() -> FwdIter&
    {
        ++_iter;
        return *this;
    }

    [[nodiscard]] constexpr auto operator++(int) -> FwdIter
    {
        FwdIter tmp(*this);
        ++(*this);
        return tmp;
    }

private:
    Iter _iter{};

    template <typename U>
    friend struct FwdIter;
};

template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(FwdIter<T> const& x, FwdIter<U> const& y) -> bool
{
    return x.base() == y.base();
}

template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(FwdIter<T> const& x, FwdIter<U> const& y) -> bool
{
    return !(x == y);
}

#endif // TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP

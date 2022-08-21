/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP
#define TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP

#include "etl/iterator.hpp"

template <typename It>
struct InIter {
    using iterator_category = etl::input_iterator_tag;
    using value_type        = typename etl::iterator_traits<It>::value_type;
    using difference_type   = typename etl::iterator_traits<It>::difference_type;
    using pointer           = It;
    using reference         = typename etl::iterator_traits<It>::reference;

    [[nodiscard]] constexpr auto base() const -> It { return iter_; }

    constexpr InIter() : iter_() { }
    explicit constexpr InIter(It it) : iter_(it) { }

    template <typename U>
    constexpr InIter(InIter<U> const& u) : iter_(u.iter_)
    {
    }

    constexpr auto operator*() const -> reference { return *iter_; }
    constexpr auto operator->() const -> pointer { return iter_; }

    constexpr auto operator++() -> InIter&
    {
        ++iter_;
        return *this;
    }
    constexpr auto operator++(int) -> InIter
    {
        InIter tmp(*this);
        ++(*this);
        return tmp;
    }

private:
    It iter_;

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

    [[nodiscard]] constexpr auto base() const -> Iter { return iter_; }

    constexpr FwdIter() = default;

    explicit constexpr FwdIter(Iter it) : iter_ { it } { }

    template <typename U>
    constexpr FwdIter(FwdIter<U> const& u) : iter_(u.iter_)
    {
    }

    [[nodiscard]] constexpr auto operator*() const -> reference { return *iter_; }

    [[nodiscard]] constexpr auto operator->() const -> pointer { return iter_; }

    constexpr auto operator++() -> FwdIter&
    {
        ++iter_;
        return *this;
    }
    [[nodiscard]] constexpr auto operator++(int) -> FwdIter
    {
        FwdIter tmp(*this);
        ++(*this);
        return tmp;
    }

private:
    Iter iter_ {};

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

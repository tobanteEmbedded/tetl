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
    using difference_type = typename etl::iterator_traits<It>::difference_type;
    using pointer         = It;
    using reference       = typename etl::iterator_traits<It>::reference;

    [[nodiscard]] constexpr auto base() const -> It { return it_; }

    constexpr InIter() : it_() { }
    explicit constexpr InIter(It it) : it_(it) { }

    template <typename U>
    constexpr InIter(const InIter<U>& u) : it_(u.it_)
    {
    }

    constexpr auto operator*() const -> reference { return *it_; }
    constexpr auto operator->() const -> pointer { return it_; }

    constexpr auto operator++() -> InIter&
    {
        ++it_;
        return *this;
    }
    constexpr auto operator++(int) -> InIter
    {
        InIter tmp(*this);
        ++(*this);
        return tmp;
    }

private:
    It it_;

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

#endif // TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP
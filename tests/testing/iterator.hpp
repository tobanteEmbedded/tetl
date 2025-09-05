// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP
#define TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/iterator.hpp>
#endif

template <typename It>
struct InIter {
    using iterator_category = etl::input_iterator_tag;
    using value_type        = typename etl::iterator_traits<It>::value_type;
    using difference_type   = typename etl::iterator_traits<It>::difference_type;
    using pointer           = It;
    using reference         = typename etl::iterator_traits<It>::reference;

    [[nodiscard]] constexpr auto base() const -> It
    {
        return _base;
    }

    constexpr InIter() = default;

    explicit constexpr InIter(It it)
        : _base(it)
    {
    }

    constexpr auto operator*() const -> reference
    {
        return *_base;
    }

    constexpr auto operator->() const -> pointer
    {
        return _base;
    }

    constexpr auto operator++() -> InIter&
    {
        ++_base;
        return *this;
    }

    constexpr auto operator++(int) -> InIter
    {
        InIter tmp(*this);
        ++(*this);
        return tmp;
    }

    friend constexpr auto operator==(InIter const& x, InIter const& y) -> bool
    {
        return x.base() == y.base();
    }

private:
    It _base{};
};

template <typename Iter>
struct FwdIter {
    using iterator_category = etl::forward_iterator_tag;
    using value_type        = typename etl::iterator_traits<Iter>::value_type;
    using difference_type   = typename etl::iterator_traits<Iter>::difference_type;
    using pointer           = Iter;
    using reference         = typename etl::iterator_traits<Iter>::reference;

    [[nodiscard]] constexpr auto base() const -> Iter
    {
        return _base;
    }

    constexpr FwdIter() = default;

    explicit constexpr FwdIter(Iter it)
        : _base{it}
    {
    }

    [[nodiscard]] constexpr auto operator*() const -> reference
    {
        return *_base;
    }

    [[nodiscard]] constexpr auto operator->() const -> pointer
    {
        return _base;
    }

    constexpr auto operator++() -> FwdIter&
    {
        ++_base;
        return *this;
    }

    [[nodiscard]] constexpr auto operator++(int) -> FwdIter
    {
        FwdIter tmp(*this);
        ++(*this);
        return tmp;
    }

    friend constexpr auto operator==(FwdIter const& x, FwdIter const& y) -> bool
    {
        return x.base() == y.base();
    }

private:
    Iter _base{};
};

#endif // TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP

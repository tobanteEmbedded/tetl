// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP
#define TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP

#include <etl/iterator.hpp>

template <typename It>
struct input_iter {
    using iterator_category = etl::input_iterator_tag;
    using value_type        = typename etl::iterator_traits<It>::value_type;
    using difference_type   = typename etl::iterator_traits<It>::difference_type;
    using pointer           = It;
    using reference         = typename etl::iterator_traits<It>::reference;

    [[nodiscard]] constexpr auto base() const -> It { return _base; }

    constexpr input_iter() = default;

    explicit constexpr input_iter(It it)
        : _base(it)
    {
    }

    constexpr auto operator*() const -> reference { return *_base; }

    constexpr auto operator->() const -> pointer { return _base; }

    constexpr auto operator++() -> input_iter&
    {
        ++_base;
        return *this;
    }

    constexpr auto operator++(int) -> input_iter
    {
        input_iter tmp(*this);
        ++(*this);
        return tmp;
    }

    friend constexpr auto operator==(input_iter const& x, input_iter const& y) -> bool { return x.base() == y.base(); }

private:
    It _base{};
};

template <typename Iter>
struct forward_iter {
    using iterator_category = etl::forward_iterator_tag;
    using value_type        = typename etl::iterator_traits<Iter>::value_type;
    using difference_type   = typename etl::iterator_traits<Iter>::difference_type;
    using pointer           = Iter;
    using reference         = typename etl::iterator_traits<Iter>::reference;

    [[nodiscard]] constexpr auto base() const -> Iter { return _base; }

    constexpr forward_iter() = default;

    explicit constexpr forward_iter(Iter it)
        : _base{it}
    {
    }

    [[nodiscard]] constexpr auto operator*() const -> reference { return *_base; }

    [[nodiscard]] constexpr auto operator->() const -> pointer { return _base; }

    constexpr auto operator++() -> forward_iter&
    {
        ++_base;
        return *this;
    }

    [[nodiscard]] constexpr auto operator++(int) -> forward_iter
    {
        forward_iter tmp(*this);
        ++(*this);
        return tmp;
    }

    friend constexpr auto operator==(forward_iter const& x, forward_iter const& y) -> bool
    {
        return x.base() == y.base();
    }

private:
    Iter _base{};
};

#endif // TETL_TESTS_ALGORITHM_ITERATOR_TYPES_HPP

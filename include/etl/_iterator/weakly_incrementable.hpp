// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_ITERATOR_WEAKLY_INCREMENTABLE_HPP
#define TETL_ITERATOR_WEAKLY_INCREMENTABLE_HPP

#include <etl/_concepts/movable.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_concepts/signed_integral.hpp>
#include <etl/_iterator/iter_difference_t.hpp>

namespace etl {

/// \ingroup iterator
template <typename Iter>
concept weakly_incrementable = etl::movable<Iter> and requires(Iter i) {
    typename etl::iter_difference_t<Iter>;
    requires etl::signed_integral<etl::iter_difference_t<Iter>>;
    { ++i } -> etl::same_as<Iter&>;
    i++;
};

} // namespace etl

#endif // TETL_ITERATOR_WEAKLY_INCREMENTABLE_HPP

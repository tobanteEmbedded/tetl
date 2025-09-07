// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_ITERATOR_PROJECTED_HPP
#define TETL_ITERATOR_PROJECTED_HPP

#include <etl/_iterator/indirect_result_t.hpp>
#include <etl/_iterator/indirectly_readable.hpp>
#include <etl/_iterator/indirectly_regular_unary_invocable.hpp>
#include <etl/_iterator/iter_difference_t.hpp>
#include <etl/_iterator/weakly_incrementable.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl {

namespace detail {

template <typename Iter, typename Proj>
struct projected_impl {
    struct type {
        using value_type = etl::remove_cvref_t<etl::indirect_result_t<Proj&, Iter>>;
        auto operator*() const -> etl::indirect_result_t<Proj&, Iter>; // not defined
    };
};

template <typename Iter, typename Proj>
    requires weakly_incrementable<Iter>
struct projected_impl<Iter, Proj> {
    struct type {
        using value_type      = etl::remove_cvref_t<etl::indirect_result_t<Proj&, Iter>>;
        using difference_type = etl::iter_difference_t<Iter>; // conditionally present

        auto operator*() const -> etl::indirect_result_t<Proj&, Iter>; // not defined
    };
};

} // namespace detail

/// \ingroup iterator
template <etl::indirectly_readable Iter, etl::indirectly_regular_unary_invocable<Iter> Proj>
using projected = etl::detail::projected_impl<Iter, Proj>::type;

} // namespace etl

#endif // TETL_ITERATOR_PROJECTED_HPP

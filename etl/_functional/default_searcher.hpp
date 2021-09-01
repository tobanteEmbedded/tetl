/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP
#define TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP

#include "etl/_algorithm/search.hpp"
#include "etl/_functional/equal_to.hpp"
#include "etl/_iterator/distance.hpp"
#include "etl/_iterator/next.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Default searcher. A class suitable for use with Searcher overload of
/// etl::search that delegates the search operation to the pre-C++17 standard
/// library's etl::search.
/// \module Utility
template <typename ForwardIter, typename Predicate = equal_to<>>
struct default_searcher {
    constexpr default_searcher(
        ForwardIter f, ForwardIter l, Predicate p = Predicate())
        : first_(f), last_(l), predicate_(p)
    {
    }

    template <typename ForwardIter2>
    constexpr auto operator()(ForwardIter2 f, ForwardIter2 l) const
        -> etl::pair<ForwardIter2, ForwardIter2>
    {
        if (auto i = etl::detail::search_impl(f, l, first_, last_, predicate_);
            i != l) {
            auto j = etl::next(i, etl::distance(first_, last_));
            return etl::pair<ForwardIter2, ForwardIter2> { i, j };
        }

        return etl::pair<ForwardIter2, ForwardIter2> { l, l };
    }

private:
    ForwardIter first_;
    ForwardIter last_;
    Predicate predicate_;
};

} // namespace etl

#endif // TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP
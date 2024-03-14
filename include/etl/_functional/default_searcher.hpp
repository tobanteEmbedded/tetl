// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP
#define TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP

#include <etl/_algorithm/search.hpp>
#include <etl/_functional/equal_to.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/pair.hpp>

namespace etl {

/// \brief Default searcher. A class suitable for use with Searcher overload of
/// etl::search that delegates the search operation to the pre-C++17 standard
/// library's etl::search.
template <typename ForwardIter, typename Predicate = equal_to<>>
struct default_searcher {
    constexpr default_searcher(ForwardIter f, ForwardIter l, Predicate p = Predicate())
        : _first(f)
        , _last(l)
        , _predicate(p)
    {
    }

    template <typename ForwardIter2>
    constexpr auto operator()(ForwardIter2 f, ForwardIter2 l) const -> etl::pair<ForwardIter2, ForwardIter2>
    {
        if (auto i = etl::search(f, l, _first, _last, _predicate); i != l) {
            auto j = etl::next(i, etl::distance(_first, _last));
            return etl::pair<ForwardIter2, ForwardIter2>{i, j};
        }

        return etl::pair<ForwardIter2, ForwardIter2>{l, l};
    }

private:
    ForwardIter _first;
    ForwardIter _last;
    Predicate _predicate;
};

} // namespace etl

#endif // TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP

// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP
#define TETL_FUNCTIONAL_DEFAULT_SEARCHER_HPP

#include "etl/_algorithm/search.hpp"
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
    default_searcher(ForwardIter f, ForwardIter l, Predicate p = Predicate())
        : first_(f), last_(l), predicate_(p)
    {
    }

    template <typename ForwardIter2>
    auto operator()(ForwardIter2 f, ForwardIter2 l) const
        -> etl::pair<ForwardIter2, ForwardIter2>
    {
        if (auto i
            = ::etl::detail::search_impl(f, l, first_, last_, predicate_);
            i != l) {
            auto j = ::etl::next(i, etl::distance(first_, last_));
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
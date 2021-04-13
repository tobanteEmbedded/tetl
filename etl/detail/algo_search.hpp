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

#ifndef TETL_DETAIL_ALGO_SEARCH_HPP
#define TETL_DETAIL_ALGO_SEARCH_HPP

namespace etl::detail
{
/// Needed by algorithm.hpp & function.hpp (default_searcher)
template <typename ForwardIter1, typename ForwardIter2,
          typename BinaryPredicate>
[[nodiscard]] constexpr auto
search_impl(ForwardIter1 first, ForwardIter1 last, ForwardIter2 sFirst,
            ForwardIter2 sLast, BinaryPredicate pred) -> ForwardIter1
{
  for (;; ++first)
  {
    auto it = first;
    for (auto sIt = sFirst;; ++it, ++sIt)
    {
      if (sIt == sLast) { return first; }
      if (it == last) { return last; }
      if (!pred(*it, *sIt)) { break; }
    }
  }
}
}  // namespace etl::detail

#endif  // TETL_DETAIL_ALGO_SEARCH_HPP

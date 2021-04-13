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

#undef NDEBUG

#include "etl/utility.hpp"      // for in_range, pair, cmp_equal, as_const
#include "etl/cassert.hpp"      // for assert
#include "etl/type_traits.hpp"  // for is_const_v, remove_reference_t

auto main() -> int
{
  using etl::as_const;
  using etl::cmp_equal;
  using etl::cmp_not_equal;
  using etl::exchange;
  using etl::is_const_v;
  using etl::make_pair;
  using etl::pair;
  using etl::remove_reference_t;
  using etl::swap;

  // SWAP
  auto v1 = 42;
  auto v2 = 100;
  swap(v1, v2);
  TETL_ASSERT(v1 == 100);
  TETL_ASSERT(v2 == 42);

  // EXCHANGE
  auto val = 1;
  TETL_ASSERT(exchange(val, 2) == 1);

  // AS CONST
  auto c = 1;
  static_assert(!is_const_v<decltype(c)>);
  static_assert(is_const_v<remove_reference_t<decltype(as_const(c))>>);

  // CMP
  static_assert(cmp_equal(42, 42));
  static_assert(!cmp_equal(42UL, 100UL));
  static_assert(cmp_not_equal(42UL, 100UL));

  // PAIR construct
  auto p1 = pair<int, float> {1, 42.0F};
  TETL_ASSERT(p1.first == 1);

  auto p2 = make_pair(2, 1.43F);
  TETL_ASSERT(p2.first == 2);

  auto p3 = p1;
  TETL_ASSERT(p3.first == 1);

  // PAIR compare
  TETL_ASSERT(p1 == p3);
  TETL_ASSERT(p1 != p2);
  TETL_ASSERT(p2 > p3);
  TETL_ASSERT(p3 < p2);

  // PAIR swap
  swap(p2, p3);
  TETL_ASSERT(p2.first == 1);
  TETL_ASSERT(p3.first == 2);

  return 0;
}

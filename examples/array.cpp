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

#include <assert.h>  // for assert
#include <stdio.h>   // for printf
#include <stdlib.h>  // for EXIT_SUCCESS

#include "etl/algorithm.hpp"  // for all_of, copy
#include "etl/array.hpp"      // for array
#include "etl/iterator.hpp"   // for begin, end

auto main() -> int
{
  using etl::all_of;
  using etl::array;
  using etl::copy;

  auto src = array {1, 2, 3, 4};  // size & type are deduced
  for (auto& item : src) { printf("%d\n", item); }

  src.fill(42);
  assert(all_of(begin(src), end(src), [](auto val) { return val == 42; }));

  decltype(src) dest = {};
  assert(all_of(begin(dest), end(dest), [](auto val) { return val == 0; }));

  copy(begin(src), end(src), begin(dest));
  assert(all_of(begin(dest), end(dest), [](auto val) { return val == 42; }));

  return EXIT_SUCCESS;
}
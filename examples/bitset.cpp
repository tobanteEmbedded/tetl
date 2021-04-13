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

#include <stdlib.h>  // for EXIT_SUCCESS

#include "etl/bitset.hpp"   // for bitset, bitset<>::reference
#include "etl/cassert.hpp"  // for TETL_ASSERT

auto main() -> int
{
  auto bits = etl::bitset<8>();
  TETL_ASSERT(bits.none() == true);
  TETL_ASSERT(bits.any() == false);
  TETL_ASSERT(bits.all() == false);
  TETL_ASSERT(bits.test(0) == false);

  bits.set(0);
  TETL_ASSERT(bits.test(0) == true);
  TETL_ASSERT(bits.count() == 1);

  bits.set(1);
  TETL_ASSERT(bits.test(1) == true);
  TETL_ASSERT(bits.count() == 2);

  bits.reset(1);
  TETL_ASSERT(bits.test(1) == false);

  bits.reset();
  TETL_ASSERT(bits.test(0) == false);

  etl::bitset<8>::reference ref = bits[0];
  TETL_ASSERT(ref == false);
  TETL_ASSERT(~ref == true);

  ref = true;
  TETL_ASSERT(ref == true);
  TETL_ASSERT(~ref == false);

  ref.flip();
  TETL_ASSERT(ref == false);
  TETL_ASSERT(~ref == true);

  return EXIT_SUCCESS;
}
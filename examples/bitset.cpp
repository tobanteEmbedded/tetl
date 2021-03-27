/*
Copyright (c) 2019-2021, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/
#undef NDEBUG

#include <assert.h>  // for assert
#include <stdlib.h>  // for EXIT_SUCCESS

#include "etl/bitset.hpp"  // for bitset, bitset<>::reference

auto main() -> int
{
  auto bits = etl::bitset<8>();
  assert(bits.none() == true);
  assert(bits.any() == false);
  assert(bits.all() == false);
  assert(bits.test(0) == false);

  bits.set(0);
  assert(bits.test(0) == true);
  assert(bits.count() == 1);

  bits.set(1);
  assert(bits.test(1) == true);
  assert(bits.count() == 2);

  bits.reset(1);
  assert(bits.test(1) == false);

  bits.reset();
  assert(bits.test(0) == false);

  etl::bitset<8>::reference ref = bits[0];
  assert(ref == false);
  assert(~ref == true);

  ref = true;
  assert(ref == true);
  assert(~ref == false);

  ref.flip();
  assert(ref == false);
  assert(~ref == true);

  return EXIT_SUCCESS;
}
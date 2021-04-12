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

#include <stdio.h>  // for printf, size_t

#include "etl/map.hpp"      // for map
#include "etl/warning.hpp"  // for ignore_unused

auto basic_usage() -> void
{
  // Create map with no elements and a capacity of 16 key-value pairs.
  auto map = etl::map<int, float, 16> {};
  printf("size: %d", static_cast<int>(map.size()));
}

// Custom key type.
struct Key
{
  constexpr explicit Key(size_t val) : val_ {val} { }

  [[nodiscard]] constexpr auto key() const -> size_t { return val_; }

  private:
  size_t val_;
};

auto custom_compare() -> void
{
  // Lambda for comparing to objects of type Key.
  constexpr auto compare
    = [](Key& lhs, Key& rhs) { return lhs.key() < rhs.key(); };

  // Create map of with <Key,int> pair with the comparator compare, no elements
  // and a capacity of 16.
  auto data = etl::map<Key, int, 16, decltype(compare)> {};
  etl::ignore_unused(data);
}

auto main() -> int
{
  basic_usage();
  custom_compare();
  return 0;
}
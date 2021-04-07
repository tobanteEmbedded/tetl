/*
Copyright (c) Tobias Hienzsch. All rights reserved.

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

#include "fuzzing.hpp"

#include "etl/algorithm.hpp"
#include "etl/cmath.hpp"
#include "etl/set.hpp"
#include "etl/string.hpp"
#include "etl/vector.hpp"

#include <set>
#include <string>

template <typename IntType>
[[nodiscard]] auto test_sort_integers(FuzzedDataProvider& provider) -> int
{
  auto generator = [&provider] { return provider.ConsumeIntegral<IntType>(); };
  auto vec       = etl::static_vector<IntType, 128> {};
  etl::generate_n(etl::back_inserter(vec), vec.capacity(), generator);

  auto etl_set = etl::static_set<IntType, 128> {begin(vec), end(vec)};
  auto std_set = std::set<IntType> {begin(vec), end(vec)};
  if (etl_set.size() != std_set.size()) { return 1; }

  etl::sort(begin(vec), end(vec));
  if (!etl::is_sorted(begin(vec), end(vec))) { return 1; }

  return 0;
}

template <typename FloatType>
[[nodiscard]] auto test_sort_floats(FuzzedDataProvider& provider) -> int
{
  auto generator
    = [&provider] { return provider.ConsumeFloatingPoint<FloatType>(); };
  auto vec = etl::static_vector<FloatType, 128> {};
  etl::generate_n(etl::back_inserter(vec), vec.capacity(), generator);

  auto etl_set = etl::static_set<FloatType, 128> {begin(vec), end(vec)};
  auto std_set = std::set<FloatType> {begin(vec), end(vec)};
  if (etl_set.size() != std_set.size()) { return 1; }

  etl::sort(begin(vec), end(vec));
  if (!etl::is_sorted(begin(vec), end(vec))) { return 1; }

  return 0;
}

[[nodiscard]] auto test_string(FuzzedDataProvider& provider) -> int
{
  auto const chars = provider.ConsumeBytesWithTerminator<char>(127, 0);

  auto etl_string = etl::static_string<128> {};
  etl::copy(chars.begin(), chars.end(), etl::back_inserter(etl_string));

  auto std_string = std::string {chars.begin(), chars.end()};

  if (etl_string.size() != std_string.size()) { return 1; }
  if (etl::strlen(chars.data()) != std::strlen(chars.data())) { return 1; }

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(etl::uint8_t const* data,
                                      etl::size_t size)
{
  if (size == 0) { return 0; }
  auto provider = FuzzedDataProvider {data, size};

  if (auto rc = test_sort_integers<etl::uint8_t>(provider); rc != 0)
  { throw rc; }
  if (auto rc = test_sort_integers<etl::uint16_t>(provider); rc != 0)
  { throw rc; }
  if (auto rc = test_sort_integers<etl::uint32_t>(provider); rc != 0)
  { throw rc; }
  if (auto rc = test_sort_integers<etl::uint64_t>(provider); rc != 0)
  { throw rc; }

  if (auto rc = test_sort_integers<etl::uint8_t>(provider); rc != 0)
  { throw rc; }
  if (auto rc = test_sort_integers<etl::uint16_t>(provider); rc != 0)
  { throw rc; }
  if (auto rc = test_sort_integers<etl::uint32_t>(provider); rc != 0)
  { throw rc; }
  if (auto rc = test_sort_integers<etl::uint64_t>(provider); rc != 0)
  { throw rc; }

  if (auto rc = test_sort_floats<etl::float_t>(provider); rc != 0) { throw rc; }
  if (auto rc = test_sort_floats<etl::double_t>(provider); rc != 0)
  { throw rc; }
  if (auto rc = test_sort_floats<long double>(provider); rc != 0) { throw rc; }

  if (auto rc = test_string(provider); rc != 0) { throw rc; }

  return 0;
}
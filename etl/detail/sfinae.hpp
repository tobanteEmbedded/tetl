/*
Copyright (c) 2019-2020, Tobias Hienzsch
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

#ifndef TAETL_SFINAE_HPP
#define TAETL_SFINAE_HPP

#define TAETL_CONCEPT_PP_CAT_(X, Y) X##Y
#define TAETL_CONCEPT_PP_CAT(X, Y) TAETL_CONCEPT_PP_CAT_(X, Y)

/**
 * @brief Requires-clause emulation with SFINAE (for templates).
 *
 * Copied from https://github.com/gnzlbg/static_vector
 */
#define TAETL_REQUIRES_(...)                                                   \
  int TAETL_CONCEPT_PP_CAT(_concept_requires_, __LINE__)                       \
    = 42,                                                                      \
    ::etl::enable_if_t                                                         \
        < (TAETL_CONCEPT_PP_CAT(_concept_requires_, __LINE__) == 43)           \
      || (__VA_ARGS__),                                                        \
    int > = 0

/**
 * @brief Requires-clause emulation with SFINAE (for "non-templates").
 *
 * Copied from https://github.com/gnzlbg/static_vector
 */
#define TAETL_REQUIRES(...)                                                    \
  template <int TAETL_CONCEPT_PP_CAT(_concept_requires_, __LINE__) = 42,       \
            ::etl::enable_if_t<                                                \
              (TAETL_CONCEPT_PP_CAT(_concept_requires_, __LINE__) == 43)       \
                || (__VA_ARGS__),                                              \
              int> = 0>

namespace etl::detail
{
template <bool CanCopy, bool CanMove>
struct sfinae_ctor_base
{
};
template <>
struct sfinae_ctor_base<false, false>
{
  sfinae_ctor_base()                        = default;
  sfinae_ctor_base(sfinae_ctor_base const&) = delete;
  sfinae_ctor_base(sfinae_ctor_base&&)      = delete;
  auto operator=(sfinae_ctor_base const&) -> sfinae_ctor_base& = default;
  auto operator=(sfinae_ctor_base&&) -> sfinae_ctor_base& = default;
};
template <>
struct sfinae_ctor_base<true, false>
{
  sfinae_ctor_base()                        = default;
  sfinae_ctor_base(sfinae_ctor_base const&) = default;
  sfinae_ctor_base(sfinae_ctor_base&&)      = delete;
  auto operator=(sfinae_ctor_base const&) -> sfinae_ctor_base& = default;
  auto operator=(sfinae_ctor_base&&) -> sfinae_ctor_base& = default;
};
template <>
struct sfinae_ctor_base<false, true>
{
  sfinae_ctor_base()                        = default;
  sfinae_ctor_base(sfinae_ctor_base const&) = delete;
  sfinae_ctor_base(sfinae_ctor_base&&)      = default;
  auto operator=(sfinae_ctor_base const&) -> sfinae_ctor_base& = default;
  auto operator=(sfinae_ctor_base&&) -> sfinae_ctor_base& = default;
};

template <bool CanCopy, bool CanMove>
struct sfinae_assign_base
{
};
template <>
struct sfinae_assign_base<false, false>
{
  sfinae_assign_base()                          = default;
  sfinae_assign_base(sfinae_assign_base const&) = default;
  sfinae_assign_base(sfinae_assign_base&&)      = default;
  auto operator=(sfinae_assign_base const&) -> sfinae_assign_base& = delete;
  auto operator=(sfinae_assign_base&&) -> sfinae_assign_base& = delete;
};
template <>
struct sfinae_assign_base<true, false>
{
  sfinae_assign_base()                          = default;
  sfinae_assign_base(sfinae_assign_base const&) = default;
  sfinae_assign_base(sfinae_assign_base&&)      = default;
  auto operator=(sfinae_assign_base const&) -> sfinae_assign_base& = default;
  auto operator=(sfinae_assign_base&&) -> sfinae_assign_base& = delete;
};
template <>
struct sfinae_assign_base<false, true>
{
  sfinae_assign_base()                          = default;
  sfinae_assign_base(sfinae_assign_base const&) = default;
  sfinae_assign_base(sfinae_assign_base&&)      = default;
  auto operator=(sfinae_assign_base const&) -> sfinae_assign_base& = delete;
  auto operator=(sfinae_assign_base&&) -> sfinae_assign_base& = default;
};
}  // namespace etl::detail

#endif  // TAETL_SFINAE_HPP
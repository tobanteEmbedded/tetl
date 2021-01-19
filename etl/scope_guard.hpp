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

#ifndef TAETL_SCOPE_GUARD_HPP
#define TAETL_SCOPE_GUARD_HPP

#include "definitions.hpp"
#include "type_traits.hpp"
#include "utility.hpp"

namespace etl
{
template <typename FuncT, typename PolicyT>
class scope_guard
{
  public:
  template <typename Functor>
  explicit scope_guard(Functor f) : func_ {etl::forward<Functor>(f)}, policy_ {}
  {
  }

  scope_guard(scope_guard&& rhs) noexcept
      : func_ {etl::move(rhs.func_)}, policy_ {etl::move(rhs.policy_)}
  {
  }

  ~scope_guard()
  {
    if (policy_) { func_(); }
  }

  void release() noexcept { policy_.release(); }

  scope_guard(scope_guard const&) = delete;
  auto operator=(scope_guard const&) -> scope_guard& = delete;
  auto operator=(scope_guard&&) -> scope_guard& = delete;

  private:
  FuncT func_;
  PolicyT policy_;
};

namespace detail
{
struct scope_exit_impl
{
  scope_exit_impl() = default;
  scope_exit_impl(scope_exit_impl&& rhs) noexcept : execute_ {rhs.execute_}
  {
    rhs.release();
  }
  void release() noexcept { execute_ = false; }
  explicit operator bool() const noexcept { return execute_; }
  bool execute_ = true;
};
}  // namespace detail

template <typename FuncT>
struct scope_exit : public scope_guard<FuncT, detail::scope_exit_impl>
{
  using scope_guard<FuncT, detail::scope_exit_impl>::scope_guard;
};

template <typename FuncT>
scope_exit(FuncT) -> scope_exit<etl::decay_t<FuncT>>;
}  // namespace etl

#endif  // TAETL_SCOPE_GUARD_HPP
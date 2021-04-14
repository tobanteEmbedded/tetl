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

#include "etl/mutex.hpp"

#include "etl/warning.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace
{
class test_mutex
{
  public:
  test_mutex(bool failOnTryLock = false) noexcept
      : failOnTryLock_ {failOnTryLock}
  {
  }

  ~test_mutex() noexcept = default;

  auto operator=(test_mutex const&) -> test_mutex& = delete;
  test_mutex(test_mutex const&)                    = delete;

  auto operator=(test_mutex&&) -> test_mutex& = default;
  test_mutex(test_mutex&&)                    = default;

  auto lock() noexcept
  {
    if (not isLocked_) { isLocked_ = true; }
  }

  auto try_lock() noexcept -> bool
  {
    if (not isLocked_ && not failOnTryLock_)
    {
      isLocked_ = true;
      return true;
    }

    return false;
  }

  auto unlock() noexcept
  {
    if (isLocked_) { isLocked_ = false; }
  }

  [[nodiscard]] auto is_locked() const noexcept { return isLocked_; }

  private:
  bool failOnTryLock_ {false};
  bool isLocked_ = false;
};
}  // namespace

TEST_CASE("mutex/lock_guard: construct", "[mutex]")
{
  SECTION("not locked")
  {
    test_mutex mtx {};
    REQUIRE_FALSE(mtx.is_locked());
    {
      etl::lock_guard lock {mtx};
      REQUIRE(mtx.is_locked());
      etl::ignore_unused(lock);
    }
    REQUIRE_FALSE(mtx.is_locked());
  }

  SECTION("already locked")
  {
    test_mutex mtx {};
    mtx.lock();
    {
      etl::lock_guard lock {mtx, etl::adopt_lock};
      REQUIRE(mtx.is_locked());
      etl::ignore_unused(lock);
    }
    REQUIRE_FALSE(mtx.is_locked());
  }
}

TEST_CASE("mutex/unique_lock: RAII", "[mutex]")
{
  SECTION("default construction")
  {
    test_mutex mtx {};
    REQUIRE_FALSE(mtx.is_locked());
    {
      etl::unique_lock<test_mutex> lock {};
      REQUIRE(lock.mutex() == nullptr);
      REQUIRE_FALSE(mtx.is_locked());
    }
    REQUIRE_FALSE(mtx.is_locked());
  }

  SECTION("lock on construction")
  {
    test_mutex mtx {};
    REQUIRE_FALSE(mtx.is_locked());
    {
      etl::unique_lock lock {mtx};
      REQUIRE(lock.mutex() == &mtx);
      REQUIRE(mtx.is_locked());
    }
    REQUIRE_FALSE(mtx.is_locked());
  }

  SECTION("try_lock on construction")
  {
    test_mutex success {false};
    REQUIRE_FALSE(success.is_locked());
    {
      etl::unique_lock lock {success, etl::try_to_lock};
      REQUIRE(success.is_locked());
    }
    REQUIRE_FALSE(success.is_locked());

    test_mutex fail {true};
    REQUIRE_FALSE(fail.is_locked());
    {
      etl::unique_lock lock {fail, etl::try_to_lock};
      REQUIRE_FALSE(fail.is_locked());
    }
    REQUIRE_FALSE(fail.is_locked());
  }

  SECTION("defer lock on construction")
  {
    test_mutex mtx {};
    REQUIRE_FALSE(mtx.is_locked());
    {
      etl::unique_lock lock {mtx, etl::defer_lock};
      REQUIRE_FALSE(mtx.is_locked());
    }
    REQUIRE_FALSE(mtx.is_locked());
  }

  SECTION("adopt lock on construction")
  {
    test_mutex mtx {};
    mtx.lock();
    REQUIRE(mtx.is_locked());
    {
      etl::unique_lock lock {mtx, etl::adopt_lock};
      REQUIRE(mtx.is_locked());
    }
    REQUIRE_FALSE(mtx.is_locked());
  }

  SECTION("move")
  {
    test_mutex mtx {};
    REQUIRE_FALSE(mtx.is_locked());
    {
      etl::unique_lock l1 {mtx};
      REQUIRE(l1.owns_lock());
      REQUIRE(mtx.is_locked());

      etl::unique_lock l2 {etl::move(l1)};
      REQUIRE_FALSE(l1.owns_lock());  // NOLINT(clang-analyzer-cplusplus.Move)
      REQUIRE(l2.owns_lock());
      REQUIRE(mtx.is_locked());

      etl::unique_lock<test_mutex> l3 {};
      l3 = etl::move(l2);
      REQUIRE_FALSE(l2.owns_lock());  // NOLINT(clang-analyzer-cplusplus.Move)
      REQUIRE(l3.owns_lock());
      REQUIRE(mtx.is_locked());
    }
    REQUIRE_FALSE(mtx.is_locked());
  }

  SECTION("swap")
  {
    test_mutex mtx {};
    REQUIRE_FALSE(mtx.is_locked());
    {
      etl::unique_lock l1 {mtx};
      REQUIRE(l1.owns_lock());
      REQUIRE(mtx.is_locked());

      decltype(l1) l2 {};
      etl::swap(l1, l2);

      REQUIRE_FALSE(l1.owns_lock());
      REQUIRE(l2.owns_lock());
      REQUIRE_FALSE(static_cast<bool>(l1));
      REQUIRE(static_cast<bool>(l2));
      REQUIRE(mtx.is_locked());
    }
    REQUIRE_FALSE(mtx.is_locked());
  }

  SECTION("release")
  {
    test_mutex mtx {};
    REQUIRE_FALSE(mtx.is_locked());
    {
      etl::unique_lock lock {mtx};
      REQUIRE(lock.owns_lock());
      REQUIRE(mtx.is_locked());

      auto* m = lock.release();
      REQUIRE_FALSE(lock.owns_lock());
      REQUIRE(m->is_locked());
    }
    REQUIRE(mtx.is_locked());
  }
}

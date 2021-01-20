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

#ifndef TAETL_MEMORY_HPP
#define TAETL_MEMORY_HPP

#include "etl/cstddef.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"
#include "etl/warning.hpp"

#include "etl/detail/sfinae.hpp"

namespace etl
{
/**
 * @brief Compressed pointer to specified size. Intended to be used as a drop in
 * replacement for native pointers.
 *
 * @details Uses the base address to calculate an offset, which will be stored
 * internally. If used on micro controllers, the base address should be set to
 * the start of RAM. See your linker script.
 */
template <typename Type, intptr_t BaseAddress = 0,
          typename StorageType = uint16_t>
class small_ptr
{
  public:
  /**
   * @brief Default construct empty small_ptr. May contain garbage.
   */
  small_ptr() = default;

  /**
   * @brief Construct from nullptr.
   */
  small_ptr(nullptr_t null) : value_ {0} { ignore_unused(null); }

  /**
   * @brief Construct from raw pointer.
   */
  small_ptr(Type* ptr) : value_ {compress(ptr)} { }

  /**
   * @brief Returns a raw pointer to Type.
   */
  [[nodiscard]] auto get() noexcept -> Type*
  {
    return reinterpret_cast<Type*>(BaseAddress + value_);
  }

  /**
   * @brief Returns a raw pointer to const Type.
   */
  [[nodiscard]] auto get() const noexcept -> Type const*
  {
    return reinterpret_cast<Type const*>(BaseAddress + value_);
  }

  /**
   * @brief Returns the compressed underlying integer address.
   */
  [[nodiscard]] auto compressed_value() const noexcept -> StorageType
  {
    return value_;
  }

  /**
   * @brief Returns a raw pointer to Type.
   */
  [[nodiscard]] auto operator->() const -> Type* { return get(); }

  /**
   * @brief Dereference pointer to Type&.
   */
  [[nodiscard]] auto operator*() -> Type& { return *get(); }

  /**
   * @brief Dereference pointer to Type const&.
   */
  [[nodiscard]] auto operator*() const -> Type const& { return *get(); }

  /**
   * @brief Pre increment of pointer.
   */
  [[nodiscard]] auto operator++(int) noexcept -> small_ptr
  {
    auto temp = *this;
    auto* ptr = get();
    ++ptr;
    value_ = compress(ptr);
    return temp;
  }

  /**
   * @brief Post increment of pointer.
   */
  [[nodiscard]] auto operator++() noexcept -> small_ptr&
  {
    auto* ptr = get();
    ptr++;
    value_ = compress(ptr);
    return *this;
  }

  /**
   * @brief Pre decrement of pointer.
   */
  [[nodiscard]] auto operator--(int) noexcept -> small_ptr
  {
    auto temp = *this;
    auto* ptr = get();
    --ptr;
    value_ = compress(ptr);
    return temp;
  }

  /**
   * @brief Post decrement of pointer.
   */
  [[nodiscard]] auto operator--() noexcept -> small_ptr&
  {
    auto* ptr = get();
    ptr--;
    value_ = compress(ptr);
    return *this;
  }

  /**
   * @brief Returns distance from this to other.
   */
  [[nodiscard]] auto operator-(small_ptr other) const noexcept -> ptrdiff_t
  {
    return get() - other.get();
  }

  /**
   * @brief Implicit conversion to raw pointer to mutable.
   */
  [[nodiscard]] operator Type*() noexcept { return get(); }

  /**
   * @brief Implicit conversion to raw pointer to const.
   */
  [[nodiscard]] operator Type const *() const noexcept { return get(); }

  private:
  [[nodiscard]] static auto compress(Type* ptr) -> StorageType
  {
    auto const obj = reinterpret_cast<intptr_t>(ptr);
    return StorageType(obj - BaseAddress);
  }

  StorageType value_;
};

/**
 * @brief Wraps a pointer and an integer value. Uses as much space as sizeof of
 * the StorageType template parameter.
 *
 * @tparam T The value_type of the wrapped pointer.
 * @tparam PointerBits How many bits to use for storing the pointer.
 * @tparam IntBits How many bits to use for storing the integer.
 * @tparam IntType The type of integer to be stored.
 * @tparam StorageType The underlying storage for both pinter & integer.
 */
template <typename T, size_t PointerBits, size_t IntBits,
          typename IntType = size_t, typename StorageType = uintptr_t>
class ptr_with_int
{
  public:
  using value_type                     = T;
  using pointer                        = T*;
  using const_pointer                  = T const*;
  using reference                      = T&;
  using const_reference                = T const&;
  using int_type                       = IntType;
  using storage_type                   = StorageType;
  static constexpr size_t pointer_bits = PointerBits;
  static constexpr size_t int_bits     = IntBits;

  /**
   * @brief Construct an empty ptr_with_int. Initialized to zero.
   */
  ptr_with_int() noexcept = default;

  /**
   * @brief Construct from nullptr.
   */
  ptr_with_int(nullptr_t /*null*/) noexcept : storage_ {0} { }

  /**
   * @brief Construct an ptr_with_int with the given pointer. The integer
   * value is initialized to zero.
   */
  explicit ptr_with_int(pointer ptr) noexcept
  {
    internal_store_ptr(ptr);
    internal_store_int(0);
  }

  /**
   * @brief Construct an ptr_with_int with the given pointer aand integer.
   */
  ptr_with_int(pointer ptr, int_type const integer) noexcept
  {
    internal_store_ptr(ptr);
    internal_store_int(integer);
  }

  /**
   * @brief Returns the contained pointer.
   */
  [[nodiscard]] auto get_ptr() noexcept -> pointer
  {
    return internal_load_ptr();
  }

  /**
   * @brief Returns the contained pointer.
   */
  [[nodiscard]] auto get_ptr() const noexcept -> pointer
  {
    return internal_load_ptr();
  }

  /**
   * @brief Returns the contained integer.
   */
  [[nodiscard]] auto get_int() const noexcept -> int_type
  {
    return internal_load_int();
  }

  /**
   * @brief Returns a raw pointer to value_type.
   */
  [[nodiscard]] auto operator->() const -> pointer { return get_ptr(); }

  /**
   * @brief Dereference pointer to value_type&.
   */
  [[nodiscard]] auto operator*() -> reference { return *get_ptr(); }

  /**
   * @brief Dereference pointer to value_type const&.
   */
  [[nodiscard]] auto operator*() const -> const_reference { return *get_ptr(); }

  /**
   * @brief Implicit conversion to raw pointer to mutable.
   */
  [[nodiscard]] operator pointer() noexcept { return get_ptr(); }

  /**
   * @brief Implicit conversion to raw pointer to const.
   */
  [[nodiscard]] operator pointer() const noexcept { return get_ptr(); }

  private:
  static_assert(int_bits >= 0);
  static_assert(pointer_bits > 0);
  static_assert(pointer_bits + int_bits == sizeof(storage_type) * 8);

  static constexpr storage_type pointer_mask = [] {
    auto mask = storage_type {0};
    for (storage_type i = 0; i < pointer_bits; ++i)
    { mask |= 1UL << (i + int_bits); }
    return mask;
  }();

  static constexpr storage_type integer_mask = [] {
    auto mask = storage_type {0};
    for (storage_type i = 0; i < int_bits; ++i) { mask |= 1UL << i; }
    return mask;
  }();

  auto internal_store_ptr(pointer ptr) noexcept -> void
  {
    auto const tmp = reinterpret_cast<uintptr_t>(ptr);
    if constexpr (int_bits > 0)
    {
      storage_ |= static_cast<storage_type>(tmp) << pointer_bits;
      return;
    }
    storage_ |= static_cast<storage_type>(tmp);
  }

  auto internal_store_int(int_type integer) noexcept -> void
  {
    storage_ |= integer;
  }

  [[nodiscard]] auto internal_load_ptr() noexcept -> pointer
  {
    if constexpr (int_bits > 0)
    {
      auto const tmp = storage_ & pointer_mask;
      return reinterpret_cast<pointer>(tmp >> pointer_bits);
    }
    return reinterpret_cast<pointer>(storage_ & pointer_mask);
  }

  [[nodiscard]] auto internal_load_ptr() const noexcept -> pointer
  {
    if constexpr (int_bits > 0)
    {
      auto const tmp = storage_ & pointer_mask;
      return reinterpret_cast<pointer>(tmp >> pointer_bits);
    }
    return reinterpret_cast<pointer>(storage_ & pointer_mask);
  }

  [[nodiscard]] auto internal_load_int() const noexcept -> int_type
  {
    return storage_ & integer_mask;
  }

  storage_type storage_ = 0;
};

template <typename T>
class default_delete
{
  public:
  constexpr default_delete() noexcept = default;

  template <typename U, TAETL_REQUIRES_((etl::is_convertible_v<U*, T*>))>
  default_delete(default_delete<U> const& /*unused*/) noexcept
  {
  }

  auto operator()(T* ptr) const noexcept -> void { delete ptr; }

  private:
  static_assert(!etl::is_function<T>::value);
  static_assert(sizeof(T));
  static_assert(!etl::is_void<T>::value);
};

template <typename T>
class default_delete<T[]>
{
  public:
  constexpr default_delete() noexcept = default;

  template <typename U,
            TAETL_REQUIRES_((etl::is_convertible_v<U (*)[], T (*)[]>))>
  default_delete(default_delete<U[]> const& /*unused*/) noexcept
  {
  }

  template <typename U,
            TAETL_REQUIRES_(etl::is_convertible_v<U (*)[], T (*)[]>)>
  auto operator()(U* array_ptr) const noexcept -> void
  {
    delete[] array_ptr;
  }

  private:
  static_assert(sizeof(T));
  static_assert(!etl::is_void<T>::value);
};

/**
 * @brief Obtains the actual address of the object or function arg, even in
 * presence of overloaded operator&.
 */
template <typename T, TAETL_REQUIRES_(etl::is_object_v<T>)>
auto addressof(T& arg) noexcept -> T*
{
  return reinterpret_cast<T*>(
    &const_cast<char&>(reinterpret_cast<const volatile char&>(arg)));
}

/**
 * @brief Obtains the actual address of the object or function arg, even in
 * presence of overloaded operator&.
 */
template <typename T, TAETL_REQUIRES_(!etl::is_object_v<T>)>
auto addressof(T& arg) noexcept -> T*
{
  return &arg;
}

/**
 * @brief Rvalue overload is deleted to prevent taking the address of const
 * rvalues.
 */
template <typename T>
auto addressof(T const&&) = delete;

/**
 * @brief If T is not an array type, calls the destructor of the object pointed
 * to by p, as if by p->~T(). If T is an array type, recursively destroys
 * elements of *p in order, as if by calling etl::destroy(etl::begin(*p),
 * etl::end(*p)).
 */
template <typename T>
constexpr auto destroy_at(T* p) -> void
{
  if constexpr (etl::is_array_v<T>)
  {
    for (auto& elem : *p) { etl::destroy_at(etl::addressof(elem)); }
  }
  else
  {
    p->~T();
  }
}

/**
 * @brief Destroys the objects in the range [first, last).
 */
template <typename ForwardIt>
constexpr auto destroy(ForwardIt first, ForwardIt last) -> void
{
  for (; first != last; ++first) { etl::destroy_at(etl::addressof(*first)); }
}

/**
 * @brief Destroys the n objects in the range starting at first.
 */
template <typename ForwardIt, typename Size>
constexpr auto destroy_n(ForwardIt first, Size n) -> ForwardIt
{
  for (; n > 0; (void)++first, --n) { etl::destroy_at(etl::addressof(*first)); }
  return first;
}

}  // namespace etl
#endif  // TAETL_MEMORY_HPP
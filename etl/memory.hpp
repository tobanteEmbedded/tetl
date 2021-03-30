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

#include "etl/bit.hpp"
#include "etl/cassert.hpp"
#include "etl/cstddef.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"
#include "etl/warning.hpp"

#include "etl/detail/sfinae.hpp"

namespace etl
{
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

/**
 * @brief The pointer_traits class template provides the standardized way to
 * access certain properties of pointer-like types.
 *
 * @details https://en.cppreference.com/w/cpp/memory/pointer_traits
 */
template <typename Ptr>
struct pointer_traits
{
  using pointer         = Ptr;
  using element_type    = typename Ptr::element_type;
  using difference_type = typename Ptr::difference_type;

  /**
   * @brief Constructs a dereferenceable pointer or pointer-like object ("fancy
   * pointer") to its argument.
   *
   * @details https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
   * @param r  Reference to an object of type element_type&.
   * @returns A pointer to r, of the type pointer_traits::pointer.
   */
  [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
  {
    return Ptr::pointer_to(r);
  }
};

/**
 * @brief The pointer_traits class template provides the standardized way to
 * access certain properties of pointer-like types.
 *
 * @details https://en.cppreference.com/w/cpp/memory/pointer_traits
 */
template <typename T>
struct pointer_traits<T*>
{
  using pointer         = T*;
  using element_type    = T;
  using difference_type = ::etl::ptrdiff_t;
  template <typename U>
  using rebind = U*;

  /**
   * @brief Constructs a dereferenceable pointer or pointer-like object ("fancy
   * pointer") to its argument.
   *
   * @details https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
   * @param r  Reference to an object of type element_type&.
   * @returns A pointer to r, of the type pointer_traits::pointer.
   */
  [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
  {
    return addressof(r);
  }
};

/**
 * @brief allocator_arg_t is an empty class type used to disambiguate the
 * overloads of constructors and member functions of allocator-aware objects.
 */
struct allocator_arg_t
{
  explicit allocator_arg_t() = default;
};

/**
 * @brief allocator_arg is a constant of type std::allocator_arg_t used to
 * disambiguate, at call site, the overloads of the constructors and member
 * functions of allocator-aware objects.
 */
inline constexpr allocator_arg_t allocator_arg {};

namespace detail
{
template <typename Type, typename Alloc, typename = void>
struct uses_allocator_impl : false_type
{
};

template <typename Type, typename Alloc>
struct uses_allocator_impl<Type, Alloc, void_t<typename Type::allocator_type>>
    : is_convertible<Alloc, typename Type::allocator_type>::type
{
};
}  // namespace detail

/**
 * @brief If T has a member typedef allocator_type which is convertible from
 * Alloc, the member constant value is true. Otherwise value is false.
 */
template <typename Type, typename Alloc>
struct uses_allocator : detail::uses_allocator_impl<Type, Alloc>::type
{
};

/**
 * @brief If T has a member typedef allocator_type which is convertible from
 * Alloc, the member constant value is true. Otherwise value is false.
 */
template <typename Type, typename Alloc>
inline constexpr auto uses_allocator_v = uses_allocator<Type, Alloc>::value;

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
  using reference                      = T&;
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
  ptr_with_int(nullptr_t /*null*/) noexcept { }

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
   * @brief Stores a new pointer.
   */
  auto set_ptr(pointer ptr) noexcept -> void { internal_store_ptr(ptr); }

  /**
   * @brief Stores a new integer value.
   */
  auto set_int(int_type const val) noexcept -> void { internal_store_int(val); }

  /**
   * @brief Returns a raw pointer to value_type.
   */
  [[nodiscard]] auto operator->() const -> pointer { return get_ptr(); }

  /**
   * @brief Dereference pointer to value_type&.
   */
  [[nodiscard]] auto operator*() -> reference { return *get_ptr(); }

  /**
   * @brief Dereference pointer to value_type&.
   */
  [[nodiscard]] auto operator*() const -> reference { return *get_ptr(); }

  /**
   * @brief Implicit conversion to raw pointer.
   */
  [[nodiscard]] operator pointer() noexcept { return get_ptr(); }

  /**
   * @brief Implicit conversion to raw pointer.
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
      assert(tmp <= (1UL << pointer_bits));
      storage_ |= static_cast<storage_type>(tmp) << pointer_bits;
      return;
    }
    storage_ |= static_cast<storage_type>(tmp);
  }

  auto internal_store_int(int_type integer) noexcept -> void
  {
    assert(integer <= (1UL << int_bits));
    storage_ &= (~integer_mask);
    storage_ |= (integer & integer_mask);
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

  private:
  storage_type storage_ {};
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
  auto operator()(U* arrayPtr) const noexcept -> void
  {
    delete[] arrayPtr;
  }

  private:
  static_assert(sizeof(T));
  static_assert(!etl::is_void<T>::value);
};

/**
 * @brief Given a pointer ptr to a buffer of size space, returns a pointer
 * aligned by the specified alignment for size number of bytes and decreases
 * space argument by the number of bytes used for alignment. The first aligned
 * address is returned.
 *
 * The function modifies the pointer only if it would be possible to fit the
 * wanted number of bytes aligned by the given alignment into the buffer. If the
 * buffer is too small, the function does nothing and returns nullptr.
 *
 * The behavior is undefined if alignment is not a power of two.
 */
[[nodiscard]] inline auto align(size_t alignment, size_t size, void*& ptr,
                                size_t& space) noexcept -> void*
{
  auto off = static_cast<size_t>(bit_cast<uintptr_t>(ptr) & (alignment - 1));
  if (off != 0) { off = alignment - off; }
  if (space < off || space - off < size) { return nullptr; }

  ptr = static_cast<char*>(ptr) + off;
  space -= off;
  return ptr;
}

}  // namespace etl
#endif  // TAETL_MEMORY_HPP
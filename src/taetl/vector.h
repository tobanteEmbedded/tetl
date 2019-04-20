/*
Copyright (c) 2019, Tobias Hienzsch
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

#ifndef TAETL_VECTOR_H
#define TAETL_VECTOR_H

#include <stdint.h>

namespace taetl
{
template <class Type>
class Vector
{
public:
  typedef Type value_type;
  typedef Type *pointer;
  typedef const Type *const_pointer;
  typedef Type &reference;
  typedef const Type &const_reference;
  typedef Type *iterator;
  typedef const Type *const_iterator;

  Vector();
  Vector(uint16_t size);
  Vector(uint16_t size, const Type &initial);
  Vector(const Vector<Type> &v);
  ~Vector();

  iterator begin() noexcept;
  const_iterator cbegin() const noexcept;

  iterator end() noexcept;
  const_iterator cend() const noexcept;

  reference front();
  reference back();

  void push_back(const Type &value);
  void pop_back();

  bool empty() const noexcept;
  uint16_t size() const noexcept;
  uint16_t capacity() const noexcept;

  void reserve(uint16_t capacity);
  void resize(uint16_t size);

  Type &operator[](uint16_t index);
  Vector<Type> &operator=(const Vector<Type> &);
  void clear();

private:
  uint16_t my_size;
  uint16_t my_capacity;
  Type *buffer;
};

template <class Type>
Vector<Type>::Vector()
{
  my_capacity = 0;
  my_size = 0;
  buffer = nullptr;
}

template <class Type>
Vector<Type>::Vector(const Vector<Type> &v)
{
  my_size = v.my_size;
  my_capacity = v.my_capacity;
  buffer = new Type[my_size];
  for (uint16_t i = 0; i < my_size; i++)
    buffer[i] = v.buffer[i];
}

template <class Type>
Vector<Type>::Vector(uint16_t size)
{
  my_capacity = size;
  my_size = size;
  buffer = new Type[size];
}

template <class Type>
Vector<Type>::Vector(uint16_t size, const Type &initial)
{
  my_size = size;
  my_capacity = size;
  buffer = new Type[size];
  for (uint16_t i = 0; i < size; i++)
    buffer[i] = initial;
  // Type();
}

template <class Type>
Vector<Type> &Vector<Type>::operator=(const Vector<Type> &v)
{
  delete[] buffer;
  my_size = v.my_size;
  my_capacity = v.my_capacity;
  buffer = new Type[my_size];
  for (uint16_t i = 0; i < my_size; i++)
    buffer[i] = v.buffer[i];
  return *this;
}

template <class Type>
typename Vector<Type>::iterator Vector<Type>::begin() noexcept
{
  return buffer;
}

template <class Type>
typename Vector<Type>::iterator Vector<Type>::end() noexcept
{
  return buffer + size();
}

template <class Type>
typename Vector<Type>::const_iterator Vector<Type>::cbegin() const noexcept
{
  return buffer;
}

template <class Type>
typename Vector<Type>::const_iterator Vector<Type>::cend() const noexcept
{
  return buffer + size();
}

template <class Type>
typename Vector<Type>::reference Vector<Type>::front()
{
  return buffer[0];
}

template <class Type>
typename Vector<Type>::reference Vector<Type>::back()
{
  return buffer[my_size - 1];
}

template <class Type>
void Vector<Type>::push_back(const Type &v)
{
  if (my_size >= my_capacity)
    this->reserve(my_capacity + 5);
  buffer[my_size++] = v;
}

template <class Type>
void Vector<Type>::pop_back()
{
  my_size--;
}

template <class Type>
void Vector<Type>::reserve(uint16_t capacity)
{
  if (buffer == nullptr)
  {
    my_size = 0;
    my_capacity = 0;
  }
  Type *Newbuffer = new Type[capacity];
  // assert(Newbuffer);
  uint16_t l_Size = capacity < my_size ? capacity : my_size;
  // copy (buffer, buffer + l_Size, Newbuffer);

  for (uint16_t i = 0; i < l_Size; i++)
    Newbuffer[i] = buffer[i];

  my_capacity = capacity;
  delete[] buffer;
  buffer = Newbuffer;
}

template <class Type>
bool Vector<Type>::empty() const noexcept
{
  if (my_size == 0)
  {
    return true;
  }

  return false;
}

template <class Type>
uint16_t Vector<Type>::size() const noexcept
{
  return my_size;
}

template <class Type>
void Vector<Type>::resize(uint16_t size)
{
  reserve(size);
  my_size = size;
}

template <class Type>
Type &Vector<Type>::operator[](uint16_t index)
{
  return buffer[index];
}

template <class Type>
uint16_t Vector<Type>::capacity() const noexcept
{
  return my_capacity;
}

template <class Type>
Vector<Type>::~Vector()
{
  delete[] buffer;
}
template <class Type>
void Vector<Type>::clear()
{
  my_capacity = 0;
  my_size = 0;
  buffer = nullptr;
}

} // namespace taetl

#endif // TAETL_VECTOR_H
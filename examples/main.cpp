#include <stdio.h>

#include "taetl/array.h"
#include "taetl/type_traits.h"
#include "taetl/vector.h"

taetl::Array<int, 16> t_array;
taetl::Vector<int> t_vector;

template <typename T>
typename taetl::enable_if<taetl::is_integral<T>::value, int>::type func(T val)
{
    return val;
}
float func(float val) { return 1; }

template <typename Type>
void foo(Type &type)
{
    (type);
}

int main()
{
    t_vector.push_back(1);
    t_vector.push_back(2);

    for (auto &item : t_vector)
    {
        foo(item);
    }

    return func(uint16_t{1});
}

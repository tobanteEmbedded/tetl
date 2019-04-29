#include <assert.h>

// TAETL
#include "taetl/definitions.hpp"

int main()
{
    assert(sizeof(taetl::size_t) == sizeof(size_t));
    return 0;
}
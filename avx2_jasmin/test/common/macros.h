#ifndef MACROS_H
#define MACROS_H

#define PASTE1(x,y) x##_##y
#define NAMESPACE1(x,y) PASTE1(x,y)

#define PASTE2(x,y,z) x##_##y##_##z
#define NAMESPACE2(x,y,z) PASTE2(x,y,z)

#endif

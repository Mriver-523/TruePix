#include "miracl.h"

#ifdef MR_KCM

#if MR_KCM == 3
#include "mrkcm3.c"
#elif MR_KCM == 4
#include "mrkcm4.c"
#else
#error Bad value for MR_KCM
#endif

#endif

#ifdef __x86_64__
#include "arch/amd64/arch.h"
#endif

#ifdef __arm__
#include "arch/arm/arch.h"
#endif

#if defined(__arm64__) || defined(__aarch64__)
#include "arch/arm64/arch.h"
#endif

#ifdef __ppc__
#include "arch/ppc/arch.h"
#endif

#ifdef __i386__
#include "arch/x86/arch.h"
#endif

#ifdef __powerpc__
#include "arch/ppc/arch.h"
#endif

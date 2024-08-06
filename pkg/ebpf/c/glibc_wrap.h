#if !defined(SET_GLIBC_LINK_VERSIONS_HEADER) && !defined(__ASSEMBLER__)
#define SET_GLIBC_LINK_VERSIONS_HEADER

#ifdef __x86_64__
__asm__(".symver exp,exp@GLIBC_2.2.5");
__asm__(".symver log,log@GLIBC_2.2.5");
__asm__(".symver log2,log2@GLIBC_2.2.5");
__asm__(".symver log2f,log2f@GLIBC_2.2.5");
__asm__(".symver pow,pow@GLIBC_2.2.5");
#elif defined(__aarch64__)
__asm__(".symver exp,exp@GLIBC_2.17");
__asm__(".symver log,log@GLIBC_2.17");
__asm__(".symver log2,log2@GLIBC_2.17");
__asm__(".symver log2f,log2f@GLIBC_2.17");
__asm__(".symver pow,pow@GLIBC_2.17");
#else
#error Unknown architecture
#endif

#endif

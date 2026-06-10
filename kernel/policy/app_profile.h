#ifndef __KSU_H_APP_PROFILE
#define __KSU_H_APP_PROFILE

#if defined(CONFIG_64BIT)
#define TIF_KSU_DISABLE_ESCAPE_WITH_ROOT 63
#else
#define TIF_KSU_DISABLE_ESCAPE_WITH_ROOT 31
#endif

// Escalate current process to root with the appropriate profile
int escape_with_root_profile(void);

#endif

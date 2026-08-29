#include <stddef.h>
#include <stdint.h>
#include <dlfcn.h>

// https://github.com/GrapheneOS/platform_bionic/blob/b95b08888b9eb6465c21d5840cce59dc463bfdef/libc/bionic/system_property_api.cpp#L78
__attribute__((used))
void compat_system_property_read_callback(const void *pi,
		void (*callback)(void *, const char *, const char *, uint32_t),
		void *cookie)
{
	typeof(compat_system_property_read_callback) *cb_fn = dlsym(RTLD_DEFAULT, "__system_property_read_callback");

	if (!!cb_fn) {
		cb_fn(pi, callback, cookie);
		return;
	}

	// https://android.googlesource.com/platform/bionic/+/0d787c1fa18c6a1f29ef9840e28a68cf077be1de/libc/bionic/system_properties.c
	int (*read_fn)(const void *, char *, char *) = dlsym(RTLD_DEFAULT, "__system_property_read");

	#define PROP_VALUE_MAX 92
	#define PROP_NAME_MAX 32
	char value[PROP_VALUE_MAX] = {0};
	char name[PROP_NAME_MAX] = {0};

	if (!read_fn || !callback)
		return;

	int serial = 0;

	// NOTE: make sure to check for pi, it is *'d right after
	if (!!pi)
		serial = read_fn(pi, name, value);

	callback(cookie, name, value, (uint32_t)serial);
}

#ifdef KSU_HAS_C23

unsigned char runner_binary[] = {
	#embed "runner_binary"
};
unsigned int runner_binary_len = sizeof(runner_binary);

#else /* ! C23 */

#define __runner_str_(x) #x
#define __runner_str(x) __runner_str_(x)

// from: https://github.com/tiann/KernelSU/blob/main/kernel/preinit/blob.S
asm(
	".section .init.rodata, \"a\"\n"
	".balign 16\n"
	".global runner_binary_start\n"
	"runner_binary_start:\n"
".incbin \"" __runner_str(KSU_PREINIT_RUNNER_BIN) "\"\n"
	".global runner_binary_end\n"
	"runner_binary_end:\n"
	".previous"
);

extern const unsigned char runner_binary_start[];
extern const unsigned char runner_binary_end[];

const unsigned char *runner_binary = runner_binary_start;
#define runner_binary_len ((unsigned int)(runner_binary_end - runner_binary_start))

#endif

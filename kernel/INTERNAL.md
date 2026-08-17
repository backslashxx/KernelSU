# Quirks / Adaptations
## C-style
- closest to GNU11, w/ some C23 / C2x backportables. 
- ^ e.g. declaration after label bypass, and macro-able features.
- pointer-centric. pointer-heavy. cast-heavy. addresses first, types are suggestions.
- assumes little endian on everything.
- some metaprogramming is actually happening (redefines, compat hacks, backports)
- plethora of compiler autism and builtins, this is by design. compiler output is king.
- minimum is gcc 4.9 / clang 10

## hooking
- wired up for aarch64 + armeabi, k3.0 ~ mainline (7.2 as of current)
- prefer syscalls and LSM always
- syscall table hooking is implemented
- theres partial kprobe/kretprobe support on boot-time hooks
- on legacy theres no kprobes/kretprobes and syscall tracepoint guarantees!
- theres no guarantee for kallsyms even!
- lots have random backports left and right, theres no abi stability guarantee at all!
- ARM64 'branch-link', callsite inline hooking support for sucompat and 6.8+ LSM.
- real-deal-but-brittle kallsyms bruteforcer to hunt ksyms.
- manual hooking is still supported and will be kept forever.

## sucompat
- tweaked for downstream
- simd-like, last word first, per word compare
- sucompat gate is tweaked too

## LSM framework
- pure function pointer on sub 6.8
- 3.x LSM scans the whole kernel to hunt for selinux_ops.
- 4.2 ~ 6.8 relies on first list member hijack.
- 6.8+ LSM relies on branch link hooking. ARM64 only.
- manual hooking also available.

## task_fix_setuid LSM
- upstream was on this before
- for seccomp disabling and umount feature
#### we don't have seccomp filter caching
- we just disable seccomp on setuid LSM
- we also reuse this seccomp status as sucompat gate
- we do this regardless of kernel version

## pkg_observer is on inode_rename LSM
- upstream was on this before
- this is faster, we filter uid
- we dont watch a full folder for shit
#### throne_tracker
- first run is synchronous by default due to FDE/FBEv1 (some)
- kthreaded on successive runs
- lock contention/double locking and race conditions are handled

## security_file_permission LSM
- we use this to avoid hooking sys_read for manual hooks
- after all we just need file pointer
- however if theres syscall table hook or kprobes_ksud, we hook it on there instead
- we also use this for "second stage apply" instead of execve_ksud

## bprm LSM
- defferent hooks for different kernels
- think of this as "after sys_execve"
- lockless argv pullouts for sulog
- might be used for something later

## selinux_hide
- we have a thin implementation downstream
- no kallsyms reliance, we hunt file operations instead, we try to keep this if possible.

## safe mode
- the implementation accepts 3x VOLUME_UP or 3x VOLUNE_DOWN to trigger safemode
- we have a dedicated input handler for this
- this will be disabled once ksud runs on_post_fs_data / ksu_is_safe_mode
- if theres no ksud to call it, it will disable itself 30s after init.rc load
- this should be enough allowance time from init.rc to post-fs-data

## build system
- unity build, single unit
- causes heavy inlining (high stack overflow risk)
- ensure inlining control (inline, noinline attributes)
- stack safety is disabled
- redefines str/mem fn's to builtins

## kthreads
- theres a lot of these on the codebase even for mundane tasks
- fearless concurrency

## hacks
#### sleeping on spinlocks
- on apply_kernelsu_rules and handle_sepolicy
- pin task to x cpu, hold rwlock, enable preempt, apply rules, do the reverse.
#### toolkit's uname hax
- since we pass arg as reference of arg on sys_reboot
- this is actually void * const char __user * const char __user *

## log / reminders
- some kernels reads 'cold + noinline' as __init, which evicts our fn. avoid this combination.
- some kernels have autistic inlining which also fucks up if we ever wanted to \__\attribute__((flatten)) (e.g. sultan and other 'optimization')



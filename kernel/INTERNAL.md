# Quirks / Adaptations

## hooking
- prefer syscalls and LSM always
- syscall table hooking is implemented but only for !CFI
- on legacy theres no kprobes/kretprobes and syscall tracepoint guarantees
- theres no guarantee for kallsyms even!
- lots have random backports left and right, theres no abi stability guarantee at all!
- theres partial kp/rp support on boot-time hooks

## sucompat
- tweaked for downstream
- last word first, per word compare, this is faster
- sucompat gate is tweaked too

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
- we also grab init_session_keyring here

## security_bprm_check LSM
- think of this as "after sys_execve"
- lockless argv pullouts for sulog
- might be used for something later

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
- redefines str/mem fn's to builtins if !FORTIFY_SOURCE

## compat handling
- always redefine/override if possible
- avoid heavy metaprogramming on macros
- if easy, backport newer kernel fn/macro's as is, then redefine.
- if hard, mimic what it does then redefine. as long as it works it is good enough.
- lots of casting hacks / type punning / void* / void** abuse are used
- kernel_compat.h for small functions
- kernel_compat.c for big functions marked __weak and tagged with extern on callee site

## kthreads
- theres a lot of these on the codebase even for mundane tasks
- fearless concurrency

## hacks
#### sleeping on spinlocks
- on apply_kernelsu_rules and handle_sepolicy
- pin task to x cpu, hold rwlock, enable preempt, jack priority, apply rules, do the reverse.
#### pointers
- this is C, theres tons of pointer hacks around.
- im not pinpointing everything
#### little endian hacks
- unused MSB reuse for tiny_sulog
- long to int dereferences
#### envp pullouts for adb root
- on execveat (kernel) hook, we pull this on envp since
- struct user_arg_ptr envp = { .ptr.native = __envp };
- __envp is const char __user *const __user * envp
- so this becomes void * const char __user *const __user * envp
- this is also used on the execve hook
#### toolkit's uname hax
- since we pass arg as reference of arg on sys_reboot
- this is actually void * const char __user * const char __user *


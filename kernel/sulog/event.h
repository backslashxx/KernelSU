#ifndef __KSU_H_SULOG_EVENT
#define __KSU_H_SULOG_EVENT

struct ksu_event_queue;
struct ksu_sulog_pending_event;

int ksu_sulog_events_init(void);
void ksu_sulog_events_exit(void);

void ksu_sulog_emit_pending(struct ksu_sulog_pending_event *pending, int retval, gfp_t gfp);

static int ksu_sulog_emit_grant_root(int retval, __u32 uid, __u32 euid, gfp_t gfp);
static int ksu_sulog_emit(__u16 event_type, const char *bprm_argv, size_t bprm_argv_len, gfp_t gfp);
static void ksu_sulog_emit_bprm(const char *filename);

struct ksu_event_queue *ksu_sulog_get_queue(void);

#endif

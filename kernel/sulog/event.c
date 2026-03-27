#define KSU_SULOG_MAX_QUEUED 256U
#define KSU_SULOG_MAX_PAYLOAD_LEN 2048U
#define KSU_SULOG_MAX_ARG_STRINGS 0x7FFFFFFF
#define KSU_SULOG_MAX_ARG_CHUNK 256U
#define KSU_SULOG_MAX_FILENAME_LEN 256U

static struct ksu_event_queue sulog_queue;

struct ksu_sulog_pending_event {
	__u16 event_type;
	void *payload;
	__u32 payload_len;
};

struct ksu_sulog_identity {
	__u32 uid;
	__u32 euid;
};

static void ksu_sulog_fill_task_info(struct ksu_sulog_event *event, __u16 event_type, int retval)
{
	event->version = KSU_SULOG_EVENT_VERSION;
	event->event_type = event_type;
	event->retval = retval;
	event->pid = task_pid_nr(current);
	event->tgid = task_tgid_nr(current);
	event->ppid = task_ppid_nr(current);
	event->uid = current_uid().val;
	event->euid = current_euid().val;
	get_task_comm(event->comm, current);
}

static void ksu_sulog_set_identity(struct ksu_sulog_event *event, const struct ksu_sulog_identity *identity)
{
	if (!identity)
		return;

	event->uid = identity->uid;
	event->euid = identity->euid;
}

static struct ksu_sulog_pending_event *ksu_sulog_capture_grant_root(const struct ksu_sulog_identity *identity, gfp_t gfp)
{
	struct ksu_sulog_pending_event *pending;
	struct ksu_sulog_event *event;

	pending = ksu_sulog_capture(KSU_SULOG_EVENT_IOCTL_GRANT_ROOT, NULL, NULL, gfp);
	if (!pending)
		return NULL;

	event = pending->payload;
	ksu_sulog_set_identity(event, identity);
	return pending;
}

int ksu_sulog_events_init(void)
{
	ksu_event_queue_init(&sulog_queue, KSU_SULOG_MAX_QUEUED, KSU_SULOG_MAX_PAYLOAD_LEN);
	return 0;
}

void ksu_sulog_events_exit(void)
{
	ksu_event_queue_destroy(&sulog_queue);
}

static void ksu_sulog_free_pending(struct ksu_sulog_pending_event *pending)
{
	if (!pending)
		return;
	kfree(pending->payload);
	kfree(pending);
}

void ksu_sulog_emit_pending(struct ksu_sulog_pending_event *pending, int retval, gfp_t gfp)
{
	struct ksu_sulog_event *event;

	if (!pending)
		return;

	event = pending->payload;
	event->retval = retval;
	ksu_event_queue_push(&sulog_queue, pending->event_type, 0, pending->payload, pending->payload_len, gfp);
	ksu_sulog_free_pending(pending);
}

int ksu_sulog_emit_grant_root(int retval, __u32 uid, __u32 euid, gfp_t gfp)
{
	if (!ksu_sulog_is_enabled())
		return 0;

	struct ksu_sulog_pending_event *pending;
	struct ksu_sulog_identity identity = {
		.uid = uid,
		.euid = euid,
	};

	pending = ksu_sulog_capture_grant_root(&identity, gfp);
	if (!pending)
		return 0;

	ksu_sulog_emit_pending(pending, retval, gfp);
	return 0;
}

struct ksu_event_queue *ksu_sulog_get_queue(void)
{
	return &sulog_queue;
}

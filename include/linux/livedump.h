/*
 * include/linux/livedump.h
 *
 * Live application dump datatype(s) and prototypes.
 */

#ifndef _LINUX_LIVEDUMP_H_
#define _LINUX_LIVEDUMP_H_

#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <asm/atomic.h>
#include <asm/siginfo.h>

/* This may be passed as 'data' argument of ptrace(PT_LIVEDUMP,...) call. */
struct livedump_param {
	int sched_nice;
	int io_prio;
	int oom_adj;
	unsigned long core_limit;
};

#ifdef __KERNEL__

#ifdef CONFIG_LIVEDUMP

/* Dumping process stages.  */
typedef enum {
	COPY_LEADER,
	COPY_THREADS,
	PERFORM_DUMP
} livedump_stage_t;

/*
 * This is the dump context. It's created only once when dumping
 * begins, and referenced from the task_struct of each clone involved
 * in dumping.
 */
struct livedump_context {
	/* Number of references to dump context. */
	struct kref ref;

	/* The thread group leader of the task being dumped. */
	struct task_struct *origin;

	/* The thread group leader of the cloned task. */
	struct task_struct *leader;

	/* Number of tasks still in the process of being cloned. */
	atomic_t nr_clone_remains;

	/* Tell the main thread the mm is duplicated. */
	struct completion dump_ready;

	/* Tell the main thread the dump is complete. */
	struct completion dump_complete;

	/* If we're requesting the dump of itself, it's performed in
	   the context of helper kernel thread. This is used to wait
	   until this thread completes. */
	struct completion thread_exit;

	/* Parameters from the user. */
	struct livedump_param param;

	/* The stage of dump we are in. */
	livedump_stage_t stage;

	/* Return status for the dump. */
	int status;
};

static inline void livedump_request(struct task_struct *tsk)
{
	force_sig_info(SIGKILL, SEND_SIG_FORCED, tsk);
}

/*
 * Same as above, but no locking on sighand->siglock.  Assumes the
 * signal can't be blocked or ignored.
 */
static inline void __livedump_request(struct task_struct *tsk)
{
	specific_send_sig_info(SIGKILL, SEND_SIG_FORCED, tsk);
}

static inline void livedump_set_status(struct livedump_context *dump,
				       long status)
{
	smp_store_mb(dump->status, status);
}

static inline int livedump_status(struct livedump_context *dump)
{
	return dump->status;
}

static inline void livedump_stage(struct livedump_context *dump,
				  livedump_stage_t stage)
{
	smp_store_mb(dump->stage, stage);
}

static inline int in_livedump(struct task_struct *tsk,
			      livedump_stage_t check_stage)
{
	return tsk->dump ? (tsk->dump->stage == check_stage) : 0;
}

extern void livedump_ref_done(struct kref *ref);

static inline struct livedump_context *get_dump(struct livedump_context *dump)
{
	kref_get(&dump->ref);
	return dump;
}

static inline void put_dump(struct livedump_context *dump)
{
	kref_put(&dump->ref, livedump_ref_done);
}

/*
 * If we are waiting, we hold a reference to the dump structure;
 * livedump_wait() decrements the reference and frees if necessary.
 */
static inline void livedump_wait(struct livedump_context *dump)
{
	wait_for_completion(&dump->dump_ready);
	current->dump = NULL;
	put_dump(dump);
}

static inline void livedump_block_signals(sigset_t *saveset)
{
	/* Save original blocked set, block everything except SIGKILL
	   which must be handled to drive dumping process. */
	spin_lock_irq(&current->sighand->siglock);
	*saveset = current->blocked;
	sigfillset(&current->blocked);
	sigdelset(&current->blocked, SIGKILL);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

static inline void livedump_unblock_signals(sigset_t *restoreset)
{
        /* Restore original blocking set. */
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = *restoreset;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

static inline void livedump_maybe_wait_dump(struct task_struct *tsk) {
	struct task_struct *leader = tsk->group_leader;

	if (leader->extra_flags & PFE_LIVEDUMP) {
		sigset_t set;

		/* This thread group performs live dumping.
		   Wait for it's completion, but be ready to
		   process SIGKILL to clone current thread. */
		livedump_block_signals(&set);
		do {
			if (schedule_timeout_interruptible(1)) {
				struct ksignal ks;
				get_signal(&ks);
			}
			barrier();
		} while (leader->extra_flags & PFE_LIVEDUMP);
		livedump_unblock_signals(&set);
	}
}

extern void livedump_clone_leader(void);
extern void livedump_clone_thread(void);
extern void livedump_perform_dump(siginfo_t *);
extern int livedump_take(struct livedump_context *dump);
extern long ptrace_livedump(struct task_struct *tsk,
			    struct livedump_param __user *param);

#endif /* CONFIG_LIVEDUMP */

#endif /* __KERNEL__ */
#endif /* _LINUX_LIVEDUMP_H_ */

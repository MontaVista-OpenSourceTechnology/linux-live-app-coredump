/*
 * include/linux/livedump.h
 *
 * Live application dump datatype(s) and prototypes.
 */

#ifndef _LINUX_LIVEDUMP_H_
#define _LINUX_LIVEDUMP_H_

#ifdef CONFIG_LIVEDUMP
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <asm/atomic.h>
#include <asm/siginfo.h>
#include <linux/oom.h>
#include <linux/ioprio.h>
#include <linux/sched.h>

struct livedump_param {
	int sched_nice;
	int io_prio;
	int oom_adj;
	unsigned long core_limit;
};

static inline void init_livedump_param(struct livedump_param *param)
{
	/* Make it ultra-low priority by default. */
	param->sched_nice = 19;
	param->io_prio = 7;
	param->oom_adj = OOM_ADJUST_MAX;
	/* Zero means using default (inherited) value. */
	param->core_limit = 0;
}

/* Dumping process stages.  */
typedef enum {
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

	/* Number of original threads still in the dump process. */
	struct kref orig_cloning;

	/* The thread group leader of the task being dumped. */
	struct task_struct *orig_leader;

	/* The thread group leader of the cloned task. */
	struct task_struct *dumped_leader;

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

static inline int task_in_livedump(struct task_struct *tsk)
{
	return tsk->dump != NULL;
}

static inline int task_in_livedump_stage(struct task_struct *tsk,
					 livedump_stage_t check_stage)
{
	return task_in_livedump(tsk) ? (tsk->dump->stage == check_stage) : 0;
}

static inline int livedump_task_is_clone_child(struct task_struct *tsk)
{
	return (tsk->dump &&
		tsk != tsk->group_leader &&
		tsk->dump->dumped_leader == tsk->group_leader);
}

static inline int livedump_task_is_clone(struct task_struct *tsk)
{
	return (tsk->dump &&
		tsk->group_leader == tsk->dump->dumped_leader);
}

static inline void livedump_wait_for_completion_sig(struct completion *c)
{
	sigset_t set;
	struct ksignal ks;

	/*
	 * This thread is currently in a livedump groupo to be cloned,
	 * but has to wait, make sure it handles signals.  The only
	 * signal that should be handled here is the SIGKILL from
	 * livedump, so no signal handling should be necessary.
	 */
	livedump_block_signals(&set);
	do {
		if (!wait_for_completion_interruptible(c))
			break;
		get_signal(&ks);
	} while (1);
	livedump_unblock_signals(&set);
}

static inline void livedump_maybe_wait_clone_done(struct task_struct *tsk)
{
	if (task_in_livedump_stage(tsk, COPY_THREADS))
		livedump_wait_for_completion_sig(&tsk->dump->dump_ready);
}

static inline void __livedump_send_sig(struct task_struct *tsk)
{
	sigaddset(&tsk->pending.signal, SIGKILL);
	signal_wake_up(tsk, 1);
}

static inline void __livedump_signal_clone(struct task_struct *tsk)
{
	assert_spin_locked(&tsk->sighand->siglock);
	atomic_inc(&current->dump->nr_clone_remains);
	tsk->dump = get_dump(current->dump);
	__livedump_send_sig(tsk);
}

static inline void livedump_signal_leader(struct task_struct *tsk)
{
	spin_lock_irq(&tsk->sighand->siglock);
	__livedump_send_sig(tsk);
	spin_unlock_irq(&tsk->sighand->siglock);
}

static inline int livedump_is_clone(unsigned long clone_flags)
{
	return clone_flags & CLONE_LIVEDUMP;
}

extern int livedump_setup_clone(struct task_struct *clone,
				unsigned long clone_flags);

static inline int livedump_check_to_clone(struct task_struct *tsk,
					  unsigned long clone_flags)
{
	int ret = 0;

	if (task_in_livedump_stage(current, COPY_THREADS) &&
	    !(clone_flags & CLONE_LIVEDUMP) && (clone_flags & CLONE_THREAD)) {
		/*
		 * This thread is currently being livedumped and the
		 * dumping process is in COPY_THREADS stage. Make sure
		 * the new thread is livedumped, too.
		 */
		__livedump_signal_clone(tsk);
	} else if (clone_flags & CLONE_LIVEDUMP) {
		ret = livedump_setup_clone(tsk, clone_flags);
	}

	return 0;
}

extern void livedump_handle_signal(siginfo_t *);
extern int do_livedump(struct task_struct *leader,
		       struct livedump_param *param);

static inline void livedump_thread_clone_done(struct task_struct *tsk)
{
	if (atomic_dec_and_test(&tsk->dump->nr_clone_remains)) {
		if (livedump_status(tsk->dump)) {
			complete_all(&tsk->dump->dump_ready);
			return;
		}

		/*
		 * All threads are cloned, or at least have tried to
		 * clone.
		 */
		livedump_stage(tsk->dump, PERFORM_DUMP);
		livedump_signal_leader(tsk->dump->dumped_leader);
	}
}

/*
 * Must be called with the sighand lock held.
 */
static inline void livedump_check_exit(struct task_struct *tsk)
{
	if (task_in_livedump(tsk)) {
		if (tsk->dump->stage == COPY_THREADS) {
			/*
			 * If livedumping and in COPY_THREADS state,
			 * that means this thread is expected to clone
			 * itself.  But at this point, it doesn't
			 * matter, so just pretend like it was never
			 * requested.
			 */
			livedump_thread_clone_done(tsk);
		}

		/* Free the dump variable if necessary. */
		put_dump(tsk->dump);
		tsk->dump = NULL;
	}
}

static inline int livedump_signal_send_ok(struct task_struct *tsk)
{
	if (livedump_task_is_clone_child(tsk)) {
		/*
		 * The livedump clone children (not clone thread group
		 * leader) can only receive signals from the clone
		 * thread group leader.  Just ignore everything else.
		 */
		if (current != tsk->group_leader)
			return 0;
	} else if (livedump_task_is_clone(tsk)) {
		/*
		 * The clone thread group leader.  It may only receive
		 * signals from the original thread group leader.
		 */
		if (current != tsk->dump->orig_leader)
			return 0;
	}

	return 1;
}

#else

static inline void livedump_maybe_wait_clone_done(struct task_struct *tsk) { }
static inline void check_signal_livedump(int signr) { }
static inline void livedump_handle_signal(void) { }
static inline int task_in_livedump(struct task_struct *tsk) { return 0; }
static inline int in_livedump(struct task_struct *tsk,
			      livedump_stage_t check_stage) { return 0; }
static inline int livedump_is_clone(unsigned long clone_flags) { return 0; }
static inline int livedump_check_to_clone(struct task_struct *tsk,
				unsigned long clone_flags) { return 0; }
static inline void livedump_check_exit(struct task_struct *tsk) { }
static inline int livedump_task_is_clone(struct task_struct *tsk) { return 0; }
static inline int livedump_task_is_clone_child(struct task_struct *tsk)
{ return 0; }
static inline int livedump_signal_send_ok(struct task_struct *tsk) { return 1; }

#endif /* CONFIG_LIVEDUMP */

#endif /* _LINUX_LIVEDUMP_H_ */

/*
 * include/linux/livedump.h
 *
 * Live application dump datatype(s) and prototypes.
 */

#ifndef _LINUX_LIVEDUMP_H_
#define _LINUX_LIVEDUMP_H_

#include <asm/siginfo.h>
#include <linux/sched.h>

#ifdef CONFIG_LIVEDUMP
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/swait.h>
#include <linux/slab.h>
#include <asm/atomic.h>
#include <asm/barrier.h>
#include <linux/oom.h>
#include <linux/ioprio.h>

/* Dumping process stages.  */
typedef enum {
	COPY_THREADS,
	PERFORM_DUMP
} livedump_stage_t;

struct livedump_param {
	int sched_nice;
	int io_prio;
	int oom_adj;
	bool core_limit_set;
	unsigned long core_limit;
};

static inline void init_livedump_param(struct livedump_param *param)
{
	/* Make it ultra-low priority by default. */
	param->sched_nice = 19;
	param->io_prio = 7;
	param->oom_adj = OOM_ADJUST_MAX;
	param->core_limit_set = false;
	param->core_limit = 0;
}

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

	/* The thread that is running the dump task. */
	struct task_struct *dump_manager;

	/* Number of tasks still in the process of being cloned. */
	atomic_t nr_clone_remains;

	/* Tell the threads the mm is duplicated. */
	struct mutex dump_ready_lock;
	unsigned int dump_ready_count;
	bool dump_ready_done;
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
	smp_rmb();
	return dump->status;
}

static inline void livedump_set_stage(struct livedump_context *dump,
				      livedump_stage_t stage)
{
	smp_store_mb(dump->stage, stage);
}

static inline livedump_stage_t livedump_stage(struct livedump_context *dump)
{
	smp_rmb();
	return dump->stage;
}

static inline void livedump_set_task_dump(struct task_struct *tsk,
					  struct livedump_context *dump)
{
	smp_store_mb(tsk->livedump, dump);
}

static inline struct livedump_context *livedump_task_dump(struct task_struct *tsk)
{
	smp_rmb();
	return tsk->livedump;
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

static inline int __task_in_livedump(struct livedump_context *dump)
{
	return dump != NULL;
}

static inline int task_in_livedump(struct task_struct *tsk)
{
	return __task_in_livedump(livedump_task_dump(tsk));
}

static inline int task_in_livedump_stage(struct livedump_context *dump,
					 livedump_stage_t check_stage)
{
	return __task_in_livedump(dump) ?
		(livedump_stage(dump) == check_stage) : 0;
}

static inline int __livedump_task_is_clone_child(struct task_struct *tsk,
						 struct livedump_context *dump)
{
	return (dump &&
		tsk != tsk->group_leader &&
		dump->dumped_leader == tsk->group_leader);
}

static inline int livedump_task_is_clone_child(struct task_struct *tsk)
{
	return __livedump_task_is_clone_child(tsk, livedump_task_dump(tsk));
}

static inline int __livedump_task_is_clone(struct task_struct *tsk,
					   struct livedump_context *dump)
{
	return (dump &&
		tsk->group_leader == dump->dumped_leader);
}

static inline int livedump_task_is_clone(struct task_struct *tsk)
{
	return __livedump_task_is_clone(tsk, livedump_task_dump(tsk));
}

static inline void livedump_wait_for_completion_sig(struct completion *c)
{
	sigset_t set;
	struct ksignal ks;

	/*
	 * This thread is currently in a livedump group to be cloned,
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

static inline void livedump_wait_for_dump_ready(struct livedump_context *dump,
						bool handle_sig)
{
	bool do_wait = false;

	mutex_lock(&dump->dump_ready_lock);
	if (!dump->dump_ready_done) {
		do_wait = true;
		dump->dump_ready_count++;
	}
	mutex_unlock(&dump->dump_ready_lock);
	if (do_wait) {
		if (handle_sig)
			livedump_wait_for_completion_sig(&dump->dump_ready);
		else
			wait_for_completion(&dump->dump_ready);
	}
}

static inline void livedump_set_dump_ready(struct livedump_context *dump)
{
	unsigned int count;

	mutex_lock(&dump->dump_ready_lock);
	dump->dump_ready_done = true;
	count = dump->dump_ready_count;
	mutex_unlock(&dump->dump_ready_lock);

	while (count) {
		complete(&dump->dump_ready);
		count--;
	}
}

static inline void livedump_maybe_wait_clone_done(struct task_struct *tsk)
{
	struct livedump_context *dump = livedump_task_dump(tsk);

	if (task_in_livedump_stage(dump, COPY_THREADS))
		livedump_wait_for_dump_ready(dump, true);
}

static inline void __livedump_send_sig(struct task_struct *tsk)
{
	sigaddset(&tsk->pending.signal, SIGKILL);
	signal_wake_up(tsk, 1);
}

static inline void __livedump_signal_clone(struct task_struct *tsk,
					   struct livedump_context *dump)
{
	assert_spin_locked(&tsk->sighand->siglock);
	atomic_inc(&dump->nr_clone_remains);
	livedump_set_task_dump(tsk, get_dump(dump));
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

static inline int livedump_check_tsk_copy(struct task_struct *tsk,
					  unsigned long clone_flags)
{
	int ret = 0;
	struct livedump_context *dump = livedump_task_dump(tsk);

	if (task_in_livedump_stage(dump, COPY_THREADS) &&
	    !(clone_flags & CLONE_LIVEDUMP) && (clone_flags & CLONE_THREAD)) {
		/*
		 * This thread is currently being livedumped and the
		 * dumping process is in COPY_THREADS stage. Make sure
		 * the new thread is livedumped, too.
		 */
		__livedump_signal_clone(tsk, dump);
	} else if (clone_flags & CLONE_LIVEDUMP) {
		ret = livedump_setup_clone(tsk, clone_flags);
	}

	return ret;
}

static inline void __livedump_thread_clone_done(struct livedump_context *dump,
						int in_lock)
{
	if (atomic_dec_and_test(&dump->nr_clone_remains)) {
		if (livedump_status(dump)) {
			livedump_set_dump_ready(dump);
			return;
		}

		/*
		 * All threads are cloned, or at least have tried to
		 * clone.
		 */
		livedump_set_stage(dump, PERFORM_DUMP);
		if (in_lock)
			__livedump_send_sig(dump->dumped_leader);
		else
			livedump_signal_leader(dump->dumped_leader);
	}
}

static inline void livedump_thread_clone_done(struct livedump_context *dump)
{
	__livedump_thread_clone_done(dump, 0);
}

/*
 * Must be called with the sighand lock held.
 */
static inline void livedump_check_tsk_exit(struct task_struct *tsk)
{
	struct livedump_context *dump = livedump_task_dump(tsk);

	if (__task_in_livedump(dump)) {
		if (livedump_stage(dump) == COPY_THREADS) {
			/*
			 * If livedumping and in COPY_THREADS state,
			 * that means this thread is expected to clone
			 * itself.  But at this point, it doesn't
			 * matter, so just pretend like it was never
			 * requested.
			 */
			__livedump_thread_clone_done(dump, 1);
		}

		/* Free the dump variable if necessary. */
		put_dump(dump);
		livedump_set_task_dump(tsk, NULL);
	}
}

static inline int livedump_check_signal_send(int sig, struct task_struct *tsk)
{
	struct livedump_context *dump = livedump_task_dump(tsk);

	if (!dump)
		return 1;

	if (__livedump_task_is_clone_child(tsk, dump)) {
		/*
		 * The livedump clone children (not clone thread group
		 * leader) can only receive signals from the clone
		 * thread group leader.  Just ignore everything else.
		 */
		if (current != dump->dumped_leader)
			return 0;
	} else if (__livedump_task_is_clone(tsk, dump)) {
		/*
		 * The clone thread group leader.  It may only receive
		 * signals from the original thread group leader.
		 */
		if (current != dump->orig_leader)
			return 0;
	} else {
		if (sig != SIGKILL)
			/* Let other signals be handled normally. */
			return 1;

		if (tsk == dump->orig_leader)
			/*
			 * The original leader should only get SIGKILLs from
			 * the dump manager.
			 */
			return current == dump->dump_manager;

		/*
		 * Other threads in the original task should only get
		 * SIGKILLs from the original leader.
		 */
		return current == dump->orig_leader;
	}

	return 1;
}

extern void livedump_handle_signal(siginfo_t *);
extern int do_livedump(struct task_struct *leader,
		       struct livedump_param *param);

#else

struct livedump_context;

static inline void livedump_set_task_dump(struct task_struct *tsk,
					  struct livedump_context *dump) { }
static inline void livedump_maybe_wait_clone_done(struct task_struct *tsk) { }
static inline void livedump_handle_signal(siginfo_t *info) { }
static inline int task_in_livedump(struct task_struct *tsk) { return 0; }
static inline int livedump_is_clone(unsigned long clone_flags) { return 0; }
static inline int livedump_check_tsk_copy(struct task_struct *tsk,
				unsigned long clone_flags) { return 0; }
static inline void livedump_check_tsk_exit(struct task_struct *tsk) { }
static inline int livedump_task_is_clone(struct task_struct *tsk) { return 0; }
static inline int livedump_task_is_clone_child(struct task_struct *tsk)
{ return 0; }
static inline int livedump_check_signal_send(int sig, struct task_struct *tsk)
{ return 1; }

#endif /* CONFIG_LIVEDUMP */

#endif /* _LINUX_LIVEDUMP_H_ */

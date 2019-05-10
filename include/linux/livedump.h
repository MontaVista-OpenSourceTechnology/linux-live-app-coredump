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
#include <linux/pid.h>
#include <asm/atomic.h>
#include <asm/barrier.h>
#include <linux/oom.h>
#include <linux/ioprio.h>

/* Dumping process stages.  */
typedef enum {
	LIVEDUMP_WAIT_STOP,	/* Waiting for all original threads to stop. */
	LIVEDUMP_COPY_THREADS,
	LIVEDUMP_PERFORM_DUMP,
	LIVEDUMP_DUMP_COMPLETE
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

	/*
	 * Namespace for the new PIDs.  We create a new namespace so
	 * we can keep the pid numbers the same for the cloned
	 * threads.
	 */
	struct pid_namespace *pid_ns;

	/* The thread group leader of the task being dumped. */
	struct task_struct *orig_leader;

	/* The thread group leader of the cloned task. */
	struct task_struct *dumped_leader;

	/* Number of threads still in the process of being stopped. */
	atomic_t nr_stop_remains;

	/* Total number of threads that are currently stopped. */
	atomic_t nr_stopped;

	/* Tell the original leader that threads are stopped. */
	struct completion stop_complete;

	/*
	 * Used by the threads to wait until everyone has stopped and the
	 * dump thread leader is created.
	 */
	struct completion dump_leader_ready;

	/* Tell the original leader that all threads have cloned. */
	struct completion threads_cloned;

	/* Tell the main thread that the clone process is done. */
	struct completion orig_leader_complete;

	/* Tell the main thread the dump is complete. */
	struct completion dump_complete;

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
	dump->status = status;
}

static inline int livedump_status(struct livedump_context *dump)
{
	return dump->status;
}

static inline void livedump_set_stage(struct livedump_context *dump,
				      livedump_stage_t stage)
{
	dump->stage = stage;
}

static inline livedump_stage_t livedump_stage(struct livedump_context *dump)
{
	return dump->stage;
}

static inline void livedump_set_task_dump(struct task_struct *tsk,
					  struct livedump_context *dump)
{
	/*
	 * Match for __task_in_livedump(), make sure we keep memory
	 * straight, especially dump->stage with tsk->dump.
	 */
	smp_wmb();
	tsk->livedump = dump;
}

static inline struct livedump_context *livedump_task_dump(
	struct task_struct *tsk)
{
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

static inline bool __task_in_livedump(struct livedump_context *dump)
{
	/*
	 * The dump variable for a thread group leader is set to
	 * an error pointer when the task goes past the point
	 * where it can be halted to complete a livedump.  That
	 * way you can't start a livedump after that point.
	 */
	if (IS_ERR_OR_NULL(dump))
		return false;
	/*
	 * Make sure memory is sane before we go on.  Otherwise
	 * dump->stage might be incorrect on other processors.
	 */
	smp_rmb();
	return true;
}

static inline bool task_in_livedump(struct task_struct *tsk)
{
	return __task_in_livedump(livedump_task_dump(tsk));
}

static inline bool task_in_livedump_stage(struct livedump_context *dump,
					  livedump_stage_t check_stage)
{
	return __task_in_livedump(dump) ?
		(livedump_stage(dump) == check_stage) : 0;
}

static inline bool __livedump_task_is_clone_child(struct task_struct *tsk,
						  struct livedump_context *dump)
{
	return (__task_in_livedump(dump) &&
		tsk != tsk->group_leader &&
		dump->dumped_leader == tsk->group_leader);
}

static inline bool livedump_task_is_clone_child(struct task_struct *tsk)
{
	return __livedump_task_is_clone_child(tsk, livedump_task_dump(tsk));
}

static inline bool __livedump_task_is_clone(struct task_struct *tsk,
					    struct livedump_context *dump)
{
	return (__task_in_livedump(dump) &&
		tsk->group_leader == dump->dumped_leader);
}

static inline bool livedump_task_is_clone(struct task_struct *tsk)
{
	return __livedump_task_is_clone(tsk, livedump_task_dump(tsk));
}

static inline bool is_livedump_sigpending(struct task_struct *tsk)
{
	return tsk->livedump_sigpending;
}

static inline void clear_livedump_sigpending(struct task_struct *tsk)
{
	 tsk->livedump_sigpending = false;
}

static inline void __livedump_send_sig(struct task_struct *tsk, bool force)
{
	tsk->livedump_sigpending = true;
	recalc_sigpending_and_wake(tsk);
	if (force)
		signal_wake_up(tsk, true);
}

static void livedump_setup_stop_task(struct task_struct *tsk,
				     struct livedump_context *dump)
{
	atomic_inc(&dump->nr_stop_remains);
	livedump_set_task_dump(tsk, get_dump(dump));
}

static inline void __livedump_signal_stop(struct task_struct *tsk,
					  struct livedump_context *dump)
{
	assert_spin_locked(&tsk->sighand->siglock);
	livedump_setup_stop_task(tsk, dump);
	__livedump_send_sig(tsk, false);
}

static inline void livedump_stop_done(struct livedump_context *dump)
{
	if (atomic_dec_and_test(&dump->nr_stop_remains))
		complete(&dump->stop_complete);
}

static inline void livedump_wait_for_stop_done(struct livedump_context *dump)
{
	int i = atomic_read(&dump->nr_stop_remains);

	if (i > 0)
		/* Only wait if we signalled some. */
		wait_for_completion(&dump->stop_complete);
}

static inline void livedump_wake_stopped(struct livedump_context *dump)
{
	int i = atomic_read(&dump->nr_stopped);

	if (i > 0) {
		/*
		 * Wake up all the waiting threads so they can clone,
		 * or just exit if there was an error in the first
		 * clone.
		 */
		for (; i > 0; i--)
			complete(&dump->dump_leader_ready);

		wait_for_completion(&dump->threads_cloned);
	}
}

/*
 * Must be called with the sighand lock held.
 */
static inline void livedump_handle_exit(struct task_struct *tsk)
{
	struct livedump_context *dump = livedump_task_dump(tsk);

	if (__task_in_livedump(dump)) {
		/* Free the dump variable if necessary. */
		livedump_set_task_dump(tsk, NULL);

		if (dump->orig_leader == tsk) {
			/*
			 * The task group leader exited before it handled
			 * the dump signal.  Just have the dump return
			 * an error.
			 */
			livedump_wait_for_stop_done(dump);
			livedump_wake_stopped(dump);
			livedump_set_status(dump, -ESRCH);
			complete(&dump->orig_leader_complete);
		} else if (livedump_stage(dump) == LIVEDUMP_WAIT_STOP &&
			   !livedump_task_is_clone(tsk)) {
			/*
			 * If livedumping and in WAIT_STOP state,
			 * that means this thread is expected to stop
			 * itself.  But at this point, it doesn't
			 * matter, so just pretend like it was never
			 * requested.
			 */
			livedump_stop_done(dump);
		}

		put_dump(dump);
	}
}

extern int livedump_setup_clone(struct task_struct *clone,
				struct livedump_context *dump,
				unsigned long clone_flags);

/*
 * Called from the copy_process code with siglock held.
 */
static inline int livedump_check_tsk_copy(struct task_struct *tsk,
					  unsigned long clone_flags)
{
	int ret = 0;
	struct livedump_context *dump = livedump_task_dump(current);

	if (task_in_livedump_stage(dump, LIVEDUMP_WAIT_STOP) &&
	    !(clone_flags & CLONE_LIVEDUMP) && (clone_flags & CLONE_THREAD)) {
		/*
		 * Current task being livedumped and the dump process
		 * is in WAIT_STOP stage. Make sure the new thread
		 * is livedumped, too.
		 */
		__livedump_signal_stop(tsk, dump);
	} else if (clone_flags & CLONE_LIVEDUMP) {
		ret = livedump_setup_clone(tsk, dump, clone_flags);
	}

	return ret;
}

/*
 * Validates that a livedump clone thread is allowed to receive a signal.
 * Used to keep other nefarious processes from messing up a livedump.
 */
static inline bool livedump_check_signal_send(int sig, struct task_struct *tsk)
{
	struct livedump_context *dump = livedump_task_dump(tsk);

	if (!__task_in_livedump(dump))
		return true;

	if (__livedump_task_is_clone_child(tsk, dump)) {
		/*
		 * The livedump clone children (not clone thread group
		 * leader) can only receive signals from the clone
		 * thread group leader.  Just ignore everything else.
		 */
		if (current != dump->dumped_leader)
			return false;
	} else if (__livedump_task_is_clone(tsk, dump)) {
		/* The clone thread group leader ignores all signals. */
		return false;
	}

	return true;
}

extern void livedump_handle_signal(siginfo_t *);
extern int do_livedump(struct task_struct *tsk,
		       struct livedump_param *param);

#else

struct livedump_context;

static inline void livedump_set_task_dump(struct task_struct *tsk,
					  struct livedump_context *dump) { }
static inline void livedump_handle_signal(siginfo_t *info) { }
static inline bool task_in_livedump(struct task_struct *tsk) { return false; }
static inline void livedump_handle_exit(struct task_struct *tsk) { }
static inline int livedump_check_tsk_copy(struct task_struct *tsk,
				unsigned long clone_flags) { return 0; }
static inline void livedump_check_tsk_exit(struct task_struct *tsk) { }
static inline bool livedump_task_is_clone(struct task_struct *tsk)
{ return false; }
static inline bool livedump_task_is_clone_child(struct task_struct *tsk)
{ return false; }
static inline bool livedump_check_signal_send(int sig, struct task_struct *tsk)
{ return true; }
static inline bool is_livedump_sigpending(struct task_struct *tsk)
{ return false; }
static inline void clear_livedump_sigpending(struct task_struct *tsk) { }

#endif /* CONFIG_LIVEDUMP */

#endif /* _LINUX_LIVEDUMP_H_ */

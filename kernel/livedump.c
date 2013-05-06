/*
 * kernel/livedump.c
 *
 * Core of live application dump.
 *
 * Actual dumping is initiated by sending SIGKILL to the thread
 * group leader, which is done by ptrace(PT_LIVEDUMP, ...). The
 * rest is signal-driven too, and performed by appropriate calls
 * from get_signal_to_deliver().
 *
 * The various interactions are rather convoluted, but here's the big
 * picture.  In the following, O is the requesting process, T is the
 * task leader being cloned (orig_leader), t is a thread being cloned,
 * C is the clone leader (dumped_leader) and c is a clone thread.
 *
 *
 * O: allocate dump
 * O: T->livedump = dump
 * O: signal(T)
 * O: wait for all cloned (dump_ready)
 * T: C = clone(T) (also clones mm)
 * T: for each (t) t->livedump = dump, signal(t)
 * T: wait for all cloned (dump_ready)
 * t: c = clone(c) (Copies mm from C)
 * t: if (I am last clone) signal(C)
 * t: wait for all cloned (dump_ready)
 * C: set mm cloned with with dump_ready (wakes all T, t, and O)
 * T,t: Return to normal operation
 * O: wait for dump_complete
 * C: dump core
 * C: wake O with dump_complete
 * C: exit
 * O: Return status
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/signal.h>
#include <linux/file.h>
#include <linux/err.h>
#include <linux/binfmts.h>
#include <linux/mutex.h>
#include <linux/livedump.h>
#include <linux/ioprio.h>
#include <linux/coredump.h>
#include <linux/kthread.h>
#include <linux/ptrace.h>

#include <asm/mmu_context.h>
#include <asm/processor.h>

int livedump_setup_clone(struct task_struct *clone, unsigned long clone_flags)
{
	struct livedump_context *dump = livedump_task_dump(current);
	struct livedump_param *param = &dump->param;
	int err, prio;
	struct sighand_struct *oldsighand = clone->sighand;

	clone->state = TASK_STOPPED;

	/*
	 * Switch over to the dumper leader's mm, group, signal, and sighand
	 * structures.
	 */
	if (clone_flags & CLONE_THREAD) {
		struct mm_struct *oldmm = clone->mm;

		atomic_inc(&dump->dumped_leader->mm->mm_users);
		clone->mm = dump->dumped_leader->mm;
		clone->active_mm = dump->dumped_leader->mm;
		mmput(oldmm);

		clone->group_leader = dump->dumped_leader;

		clone->signal = dump->dumped_leader->signal;

		atomic_inc(&dump->dumped_leader->sighand->count);
		clone->sighand = dump->dumped_leader->sighand;
		__cleanup_sighand(oldsighand);

		livedump_set_task_dump(clone, get_dump(dump));
	}

	set_user_nice(clone, param->sched_nice);

	/* Clone will have inherited I/O scheduling class, but new priority. */
	prio = get_task_ioprio(clone);
	if (prio < 0)
		return prio;
	err = set_task_ioprio(clone, IOPRIO_PRIO_VALUE
			      (IOPRIO_PRIO_CLASS(prio), param->io_prio));
	if (err)
		return err;

	clone->signal->oom_score_adj = param->oom_adj;

	/* This is for the leader only, as sys_setrlimit() does. */
	if (!(clone_flags & CLONE_THREAD) && param->core_limit_set) {
		clone->signal->rlim[RLIMIT_CORE].rlim_cur = param->core_limit;
		clone->signal->rlim[RLIMIT_CORE].rlim_max = param->core_limit;
	}

	return 0;
}

/*
 * Copy current task_struct, make clone suitable for dumping.
 */
static struct task_struct *livedump_clone(unsigned long clone_flags)
{
	/* We use the same pid as the cloned thread. */
	struct pid *pid = get_task_pid(current, PIDTYPE_PID);
	struct pt_regs regs;
	struct task_struct *clone;

	regs = *task_pt_regs(current);
	clone = copy_process(CLONE_LIVEDUMP | clone_flags,
			     KSTK_ESP(current), 0, NULL, pid, 0, 0,
			     NUMA_NO_NODE);
	if (IS_ERR(clone)) {
		put_pid(pid);
		return clone;
	}

	return clone;
}

/*
 * If we are waiting, we hold a reference to the dump structure;
 * livedump_wait() decrements the reference and frees if necessary.
 */
static void livedump_wait(struct livedump_context *dump)
{
	if (dump->orig_leader != current)
		/* The leader is cleared when the dump is complete. */
		livedump_set_task_dump(current, NULL);
	livedump_thread_clone_done(dump);
	livedump_wait_for_dump_ready(dump, false);
	if (dump->orig_leader == current) {
		/*
		 * We hold the original leader's dump variable until
		 * here so that you can't start another dump until
		 * this is complete.
		 */
		livedump_set_task_dump(dump->orig_leader, NULL);
		complete(&dump->dump_complete);
	}
	put_dump(dump);
}

/*
 * Clone one thread, force the new thread group leader
 * to perform the dump if we're the last thread cloned.
 */
static void livedump_clone_thread(void)
{
	struct livedump_context *dump = livedump_task_dump(current);
	struct task_struct *clone;

	BUG_ON(!dump);

	if (current == dump->orig_leader) {
		struct task_struct *p;

		atomic_set(&dump->nr_clone_remains, 1);

		clone = livedump_clone(CLONE_PARENT);
		if (IS_ERR(clone)) {
			livedump_set_status(dump, PTR_ERR(clone));
			livedump_set_task_dump(current, NULL);
			livedump_set_dump_ready(dump);
			put_dump(dump);
			return;
		}

		dump->dumped_leader = clone;
		livedump_set_task_dump(clone, get_dump(dump));

		/*
		 * Request all the other threads to clone.
		 * siglock protects the thread list.
		 */
		spin_lock_irq(&current->sighand->siglock);
		for (p = next_thread(current); p != current;
						p = next_thread(p))
			__livedump_signal_clone(p, dump);
		spin_unlock_irq(&current->sighand->siglock);
	} else {
		clone = livedump_clone(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM);
		if (IS_ERR(clone)) {
			/*
			 * Save first error we've encountered. Other threads
			 * may have failed to clone themselves too, but their
			 * errors will be discarded.
			 */
			if (!livedump_status(dump))
				livedump_set_status(dump, PTR_ERR(clone));
		}
	}
	livedump_wait(dump);
}

/*
 * Complete the dump in the cloned leader. Core file is dumped only if
 * dump->status is 0 before dumping, i.e. there was no errors on the
 * previous stages.
 */
static void livedump_perform_dump(siginfo_t *info,
				  struct livedump_context *dump)
{
	sigset_t blocked;
	long status;

	BUG_ON(!dump);
	current->flags |= PF_SIGNALED;

	status = livedump_status(dump);
	if (status)
		/* There was some error, while copying mm or earlier.
		   Allow original threads to run, but do not dump core. */
		livedump_set_status(dump, status);
	livedump_set_dump_ready(dump);
	if (status)
		goto out;

	/*
	 * Everything looks valid, may dump core. All signals are
	 * blocked to avoid magic -ERESTARTSYS errors comes due to I/O
	 * via NFS.
	 */
	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);

	status = do_coredump(info);

	livedump_set_status(dump, status);
out:
	complete(&dump->dump_complete);
	do_group_exit(SIGKILL);
	/* NOTREACHED */
}

void livedump_handle_signal(siginfo_t *info)
{
	struct livedump_context *dump = livedump_task_dump(current);

	switch (livedump_stage(dump)) {
	case COPY_THREADS:
		livedump_clone_thread();
		break;
	case PERFORM_DUMP:
		if (thread_group_leader(current))
			livedump_perform_dump(info, dump);
		else
			BUG();
		break;
	}
}

void livedump_ref_done(struct kref *ref)
{
	kfree(container_of(ref, struct livedump_context, ref));
}

static int livedump_take(struct livedump_context *dump)
{
	int status;

	get_dump(dump);
	/* Initialize the rest of livedump context. */
	dump->dump_manager = current;
	livedump_set_status(dump, 0);
	livedump_set_stage(dump, COPY_THREADS);
	init_completion(&dump->dump_complete);
	mutex_init(&dump->dump_ready_lock);
	dump->dump_ready_done = false;
	dump->dump_ready_count = 1; /* We will wait. */
	init_completion(&dump->dump_ready);

	livedump_signal_leader(dump->orig_leader);

	wait_for_completion(&dump->dump_ready);
	status = livedump_status(dump);
	if (status)
		goto out;

	/*
	 * Wait for two completions, one from the original task leader
	 * and one from the dumped task leader.  This way we know that
	 * both stages are complete.  If we don't wait for the
	 * original task leader, we can return before it has set its
	 * live dump variable to NULL.
	 */
	wait_for_completion(&dump->dump_complete);
	wait_for_completion(&dump->dump_complete);
	status = livedump_status(dump);
out:
	put_dump(dump);

	return status;
}

static int livedump_dumper_thread(void *arg)
{
	struct livedump_context *dump = arg;

	/* Block all signals just to be safe. */
	spin_lock_irq(&current->sighand->siglock);
	sigfillset(&current->blocked);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
	livedump_take(dump);
	complete_and_exit(&dump->thread_exit, 0);
}

int do_livedump(struct task_struct *orig_leader, struct livedump_param *param)
{
	int ret = 0;
	struct livedump_context *dump = NULL;
	struct task_struct *dumper;

	if (param->sched_nice < -20 ||
			param->sched_nice > 19 ||
			param->io_prio < 0 ||
			param->io_prio >= IOPRIO_BE_NR ||
			param->oom_adj < OOM_DISABLE ||
			param->oom_adj > OOM_ADJUST_MAX ||
			param->core_limit > RLIM_INFINITY)
		return -EINVAL;
	else if ((param->sched_nice < 0 && !capable(CAP_SYS_NICE)) ||
			(param->core_limit && !capable(CAP_SYS_RESOURCE)))
		return -EPERM;

	dump = kmalloc(sizeof *dump, GFP_KERNEL);
	if (!dump)
		return -ENOMEM;

	dump->param = *param;
	kref_init(&dump->ref);
	dump->orig_leader = orig_leader;
	dump->dumped_leader = NULL;

	/*
	 * Do not dump the task being ptraced, kernel thread,
	 * or task which is exiting or handling fatal signal.
	 */
	task_lock(orig_leader);
	if ((orig_leader->ptrace & PT_PTRACED) ||
            (!orig_leader->mm) ||
            (orig_leader->flags & PF_SIGNALED) ||
            (orig_leader->signal->flags & SIGNAL_GROUP_EXIT))
                ret = -EINVAL;
	else if (task_in_livedump(orig_leader))
		ret = -EINPROGRESS;
	else
		livedump_set_task_dump(orig_leader, dump);
	task_unlock(orig_leader);
	if (ret)
		goto out;

	/* We may start the dump. */
	if (current->group_leader == orig_leader) {
		/*
		 * Current is a member of the thread group lead by the
		 * dumped task.  Since the task can't dump itself nor
		 * it's leader, a special kernel thread (dumper) will do
		 * it.
		 */
		init_completion(&dump->thread_exit);
		dumper = kthread_run(livedump_dumper_thread, dump, "dump_%s",
				     current->comm);
		if (IS_ERR(dumper)) {
			livedump_set_task_dump(orig_leader, NULL);
			kfree(dump);
			ret = PTR_ERR(dumper);
		} else {
			livedump_wait_for_completion_sig(&dump->thread_exit);
			ret = livedump_status(dump);
		}
	} else {
		/*
		 * When current and leader are not in the same
		 * thread group, things are much easier...
		 */
		ret = livedump_take(dump);
	}
out:
	return ret;
}

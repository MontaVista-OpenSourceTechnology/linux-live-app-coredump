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
 * O: wait for original thread leader complete
 * T: for each (t) t->livedump = dump, signal(t)
 * T: wait for all threads stopped
 * T: C = clone(T) (also clones mm)
 * T: for each (t) wake up
 * t: c = clone(c) (Copies mm from C)
 * t: if (I am last clone) tell T clone is complete
 * t: Return to normal operation
 * T: Tell O that the clone is ready
 * T: Return to normal operation
 * O: Wake up O
 * O: wait for dump_complete
 * C: dump core
 * C: wake O with dump_complete
 * C: exit
 * O: Return status
 */

#include <linux/kernel.h>
#include <linux/sched/task_stack.h>
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

int livedump_setup_clone(struct task_struct *clone,
			 struct livedump_context *dump,
			 unsigned long clone_flags)
{
	struct livedump_param *param = &dump->param;
	int err, prio;

	clone->state = TASK_STOPPED;

	/*
	 * Make sure we fall into the signal handler when we exit.
	 */
	set_tsk_thread_flag(clone, TIF_SIGPENDING);
	clone->livedump_sigpending = true;

	/*
	 * The clone is done with all signals blocked so there is no
	 * error caused by a signal pending in the original thread.
	 * But SIGKILL is needed to take the coredump, so re-add it.
	 */
	sigdelset(&clone->blocked, SIGKILL);

	/*
	 * Switch over to the dumper leader's mm, group, signal, and sighand
	 * structures.
	 */
	if (clone_flags & CLONE_THREAD) {
		struct mm_struct *oldmm = clone->mm;
		struct sighand_struct *oldsighand = clone->sighand;

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

static void livedump_block_signals(sigset_t *saveset)
{
	/* Save original blocked set, block everything. */
	spin_lock_irq(&current->sighand->siglock);
	*saveset = current->blocked;
	sigfillset(&current->blocked);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

static void livedump_unblock_signals(sigset_t *restoreset)
{
        /* Restore original blocking set. */
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = *restoreset;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

/*
 * Copy current task_struct, make clone suitable for dumping.
 */
static struct task_struct *livedump_clone(struct livedump_context *dump,
					  unsigned long clone_flags)
{
	/* We use the same pid as the cloned thread. */
	struct pid *pid, *opid = get_task_pid(current, PIDTYPE_PID);
	struct task_struct *clone;
	sigset_t saveset;

	pid = alloc_pid_nr(dump->pid_ns, pid_vnr(opid));
	put_pid(opid);
	if (IS_ERR(pid))
		return ERR_PTR(PTR_ERR(pid));

	/*
	 * copy_process() will error if any signals are pending for the
	 * thread.  So make sure no signals are pending.
	 */
	livedump_block_signals(&saveset);
	clone = copy_process(CLONE_LIVEDUMP | clone_flags,
			     KSTK_ESP(current), 0, NULL, pid, 0, 0,
			     NUMA_NO_NODE);
	livedump_unblock_signals(&saveset);
	if (IS_ERR(clone))
		free_pid(pid);

	return clone;
}

/*
 * Clone one thread, force the new thread group leader
 * to perform the dump if we're the last thread cloned.
 */
static void livedump_clone_leader(struct livedump_context *dump)
{
	struct task_struct *clone;

	livedump_wait_for_stop_done(dump);
	livedump_set_stage(dump, LIVEDUMP_COPY_THREADS);

	/* Now create the clone leader. */
	clone = livedump_clone(dump, CLONE_PARENT);
	if (IS_ERR(clone)) {
		livedump_set_status(dump, PTR_ERR(clone));
	} else {
		dump->dumped_leader = clone;
		livedump_set_task_dump(clone, get_dump(dump));
	}

	livedump_wake_stopped(dump);

	if (IS_ERR(clone)) {
		livedump_set_task_dump(current, NULL);
		complete(&dump->orig_leader_complete);
		put_dump(dump);
		return;
	}

	/*
	 * Wait for all threads to complete before setting our dump
	 * variable to NULL, this avoids starting another dump before
	 * all the threads in this process are ready.
	 */
	dump->orig_leader = NULL;
	livedump_set_task_dump(current, NULL);

	complete(&dump->orig_leader_complete);
	put_dump(dump);
}

static void livedump_clone_child(struct livedump_context *dump)
{
	struct task_struct *clone;

	clone = livedump_clone(dump,
			       CLONE_THREAD | CLONE_SIGHAND | CLONE_VM);
	if (IS_ERR(clone)) {
		/*
		 * Save first error we've encountered. Other threads
		 * may fail to clone themselves too, but their errors
		 * will be discarded.
		 */
		if (!livedump_status(dump))
			livedump_set_status(dump, PTR_ERR(clone));
	}
}

static inline void livedump_thread_clone_done(struct livedump_context *dump)
{
	if (atomic_dec_and_test(&dump->nr_stopped))
		complete(&dump->threads_cloned);
}

/*
 * A thread that needs to be cloned needs to stop.
 */
static void livedump_handle_stop(struct livedump_context *dump)
{
	atomic_inc(&dump->nr_stopped);
	livedump_stop_done(dump);

	wait_for_completion(&dump->dump_leader_ready);
	if (dump->dumped_leader)
		/* Don't clone unless first clone succeeded. */
		livedump_clone_child(dump);

	livedump_set_task_dump(current, NULL);
	livedump_thread_clone_done(dump);
	put_dump(dump);

	/* The thread is now free to run. */
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

	current->flags |= PF_SIGNALED;

	if (!livedump_status(dump)) {
		/*
		 * Everything looks valid, may dump core. All signals
		 * are blocked to avoid magic -ERESTARTSYS errors
		 * comes due to I/O via NFS.
		 */
		sigfillset(&blocked);
		sigprocmask(SIG_BLOCK, &blocked, NULL);
		flush_signals(current);

		status = do_coredump(info);

		livedump_set_stage(dump, LIVEDUMP_DUMP_COMPLETE);
		livedump_set_status(dump, status);
	}
	complete(&dump->dump_complete);
	do_group_exit(SIGKILL);
	/* NOTREACHED */
}

void livedump_handle_signal(siginfo_t *info)
{
	struct livedump_context *dump = livedump_task_dump(current);

	if (!__task_in_livedump(dump))
		return;

	if (livedump_task_is_clone_child(current)) {
		/*
		 * Clone children are never allowed to run, so trap them
		 * here until they are killed.
		 */
		schedule_timeout_killable(1);
		current->livedump_sigpending = true;
		recalc_sigpending();
		return;
	}

	switch (livedump_stage(dump)) {
	case LIVEDUMP_WAIT_STOP:
		if (current == dump->orig_leader)
			livedump_clone_leader(dump);
		else
			livedump_handle_stop(dump);
		break;
	case LIVEDUMP_PERFORM_DUMP:
		BUG_ON(!__livedump_task_is_clone(current, dump) ||
		       !thread_group_leader(current));
		livedump_perform_dump(info, dump);
		/* NOTREACHED */
		BUG();
		break;
	default:
		BUG();
	}
}

void livedump_ref_done(struct kref *ref)
{
	struct livedump_context *dump = container_of(ref,
						     struct livedump_context,
						     ref);

	put_pid_ns(dump->pid_ns);
	kfree(dump);
}

/*
 * Signal all threads in the process except the thread passed in and
 * the original leader thread.
 */
static void livedump_sig_threads(struct livedump_context *dump,
				 struct task_struct *t)
{
	struct task_struct *p;

	/*
	 * Request all the other threads to stop.  siglock protects
	 * the thread list, and keeps any thread from handling the
	 * signal until the lock is released, to avoid a thread handling
	 * the signal and decrementing nr_stop_remains to zero before
	 * the increment for the next thread is done.
	 */
	spin_lock_irq(&t->sighand->siglock);
	for (p = next_thread(t); p != t; p = next_thread(p)) {
		if (p != dump->orig_leader)
			__livedump_signal_stop(p, dump);
	}
	spin_unlock_irq(&t->sighand->siglock);
}

static inline void livedump_signal_leader(struct task_struct *tsk,
					  bool force)
{
	spin_lock_irq(&tsk->sighand->siglock);
	__livedump_send_sig(tsk, force);
	spin_unlock_irq(&tsk->sighand->siglock);
}

int do_livedump(struct task_struct *tsk, struct livedump_param *param)
{
	int ret = 0;
	struct livedump_context *dump;
	struct task_struct *orig_leader;

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

	dump = kmalloc(sizeof(*dump), GFP_KERNEL);
	if (!dump)
		return -ENOMEM;

	dump->param = *param;
	kref_init(&dump->ref);
	dump->dumped_leader = NULL;

	/* Initialize the rest of livedump context. */
	livedump_set_status(dump, 0);
	livedump_set_stage(dump, LIVEDUMP_WAIT_STOP);
	init_completion(&dump->stop_complete);
	init_completion(&dump->dump_leader_ready);
	init_completion(&dump->threads_cloned);
	init_completion(&dump->orig_leader_complete);
	init_completion(&dump->dump_complete);
	atomic_set(&dump->nr_stop_remains, 0);
	atomic_set(&dump->nr_stopped, 0);

	/*
	 * The parent PID and user namespace for the new
	 * threads aren't important, we just need something
	 * there to make the code work.
	 */
	dump->pid_ns = copy_pid_ns(CLONE_NEWPID, &init_user_ns,
				   &init_pid_ns);
	if (IS_ERR(dump->pid_ns)) {
		ret = PTR_ERR(dump->pid_ns);
		goto out_err;
	}

	/*
	 * Do not dump a task being ptraced, kernel thread, or task
	 * which is exiting or handling fatal signal.
	 */
	write_lock_irq(&tasklist_lock);
	orig_leader = tsk->group_leader;
	dump->orig_leader = orig_leader;
	if (orig_leader->ptrace & PT_PTRACED ||
            !orig_leader->mm ||
            orig_leader->flags & PF_SIGNALED ||
            orig_leader->signal->flags & SIGNAL_GROUP_EXIT)
                ret = -EINVAL;
	else if (livedump_task_dump(orig_leader))
		/* leader is already in a dump or exiting. */
		ret = -EINPROGRESS;
	else
		livedump_set_task_dump(orig_leader, get_dump(dump));

	write_unlock_irq(&tasklist_lock);
	if (ret)
		goto out_err;

	if (current->group_leader == orig_leader) {
		if (current != orig_leader)
			/*
			 * Do this first.  Otherwise all the other
			 * threads may get set up then run their
			 * signal handlers, decrementing
			 * nr_stop_remains to zero before the current
			 * task increments nr_stop_remains, resulting
			 * in the dump process continuing when it
			 * shouldn't.
			 */
			livedump_setup_stop_task(current, dump);
		livedump_sig_threads(dump, current);

		if (current == orig_leader) {
			/*
			 * We are the original leader, just start the
			 * process directly.
			 */
			livedump_clone_leader(dump);
		} else {
			/*
			 * We are a non-leader of the original process,
			 * pretend like we were signaled and wake the
			 * leader.
			 */
			livedump_signal_leader(orig_leader, false);
			livedump_handle_stop(dump);
		}
	} else {
		livedump_sig_threads(dump, orig_leader);

		/* Tell the leader to start the dump. */
		livedump_signal_leader(orig_leader, false);
	}

	wait_for_completion(&dump->orig_leader_complete);
	ret = livedump_status(dump);

	if (dump->dumped_leader) {
		/*
		 * If the dumped leader was created, make sure to wake
		 * it up no matter what.
		 */
		livedump_set_stage(dump, LIVEDUMP_PERFORM_DUMP);
		livedump_signal_leader(dump->dumped_leader, true);
	}

	if (!ret) {
		/* Wait for the dumped leader to save the core. */
		wait_for_completion(&dump->dump_complete);
		ret = livedump_status(dump);
	}

	put_dump(dump);

	return ret;

out_err:
	kfree(dump);
	return ret;
}

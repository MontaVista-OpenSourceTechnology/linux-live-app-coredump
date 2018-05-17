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

/*
 * Copy current task_struct, make clone suitable for dumping.
 */
static struct task_struct *livedump_clone(struct livedump_context *dump,
					  unsigned long clone_flags)
{
	/* We use the same pid as the cloned thread. */
	struct pid *pid, *opid = get_task_pid(current, PIDTYPE_PID);
	struct task_struct *clone;

	pid = alloc_pid_nr(dump->pid_ns, pid_vnr(opid));
	put_pid(opid);
	if (IS_ERR(pid))
		return ERR_PTR(PTR_ERR(pid));

	clone = copy_process(CLONE_LIVEDUMP | clone_flags,
			     KSTK_ESP(current), 0, NULL, pid, 0, 0,
			     NUMA_NO_NODE);
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
	struct task_struct *p;
	int i;

	BUG_ON(current != dump->orig_leader);

	atomic_set(&dump->nr_stop_remains, 0);
	atomic_set(&dump->nr_stopped, 0);

	/*
	 * Request all the other threads to stop.  siglock protects
	 * the thread list.
	 */
	spin_lock_irq(&current->sighand->siglock);
	livedump_set_stage(dump, LIVEDUMP_WAIT_STOP);
	for (p = next_thread(current); p != current; p = next_thread(p))
		__livedump_signal_stop(p, dump);
	spin_unlock_irq(&current->sighand->siglock);

	i = atomic_read(&dump->nr_stop_remains);
	if (i > 0)
		/* Only wait if we signalled some. */
		wait_for_completion(&dump->stop_complete);

	/* Now create the clone leader. */
	clone = livedump_clone(dump, CLONE_PARENT);
	if (IS_ERR(clone)) {
		livedump_set_status(dump, PTR_ERR(clone));
		livedump_set_task_dump(current, NULL);
		complete(&dump->orig_leader_complete);
		put_dump(dump);
		return;
	}

	dump->dumped_leader = clone;
	livedump_set_task_dump(clone, get_dump(dump));

	i = atomic_read(&dump->nr_stopped);
	if (i > 0) {
		/* Wake up all the waiting threads so they can clone. */
		for (; i >= 0; i--)
			complete(&dump->dump_leader_ready);

		wait_for_completion(&dump->threads_cloned);
	}

	/*
	 * Wait for all threads to complete before setting our dump
	 * variable to NULL, this avoids starting another dump before
	 * all the threads in this process are ready.
	 */
	livedump_set_task_dump(current, NULL);
	put_dump(dump);

	complete(&dump->orig_leader_complete);
}

static void livedump_clone_child(struct livedump_context *dump)
{
	struct task_struct *clone;

	BUG_ON(current == dump->orig_leader);

	clone = livedump_clone(dump,
			       CLONE_THREAD | CLONE_SIGHAND | CLONE_VM);
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

/*
 * A thread that needs to be cloned needs to stop.
 */
static void livedump_handle_stop(struct livedump_context *dump)
{
	atomic_inc(&dump->nr_stopped);
	livedump_stop_done(dump);

	wait_for_completion(&dump->dump_leader_ready);
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

	/*
	 * Everything looks valid, may dump core. All signals are
	 * blocked to avoid magic -ERESTARTSYS errors comes due to I/O
	 * via NFS.
	 */
	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);

	status = do_coredump(info);

	livedump_set_stage(dump, LIVEDUMP_DUMP_COMPLETE);
	livedump_set_status(dump, status);

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
	case LIVEDUMP_INIT:
		livedump_clone_leader(dump);
		break;
	case LIVEDUMP_WAIT_STOP:
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

int do_livedump(struct task_struct *orig_leader, struct livedump_param *param)
{
	int ret = 0;
	struct livedump_context *dump;

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
	get_dump(dump);
	dump->dumped_leader = NULL;

	/* Initialize the rest of livedump context. */
	livedump_set_status(dump, 0);
	livedump_set_stage(dump, LIVEDUMP_INIT);
	init_completion(&dump->stop_complete);
	init_completion(&dump->dump_leader_ready);
	init_completion(&dump->threads_cloned);
	init_completion(&dump->orig_leader_complete);
	init_completion(&dump->dump_complete);

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
	 * which is exiting or handling fatal signal.  A task may not
	 * dump itself.
	 */
	write_lock_irq(&tasklist_lock);
	orig_leader = orig_leader->group_leader;
	dump->orig_leader = orig_leader;
	if (orig_leader->ptrace & PT_PTRACED ||
            !orig_leader->mm ||
            orig_leader->flags & PF_SIGNALED ||
            orig_leader->signal->flags & SIGNAL_GROUP_EXIT ||
	    current->group_leader == orig_leader)
                ret = -EINVAL;
	else if (livedump_task_dump(orig_leader))
		/* leader is already in a dump or exiting. */
		ret = -EINPROGRESS;
	else
		livedump_set_task_dump(orig_leader, dump);

	write_unlock_irq(&tasklist_lock);
	if (ret)
		goto out_err;

	/* We may start the dump. */
	livedump_signal_leader(orig_leader);

	wait_for_completion(&dump->orig_leader_complete);
	ret = livedump_status(dump);
	if (!ret) {
		/* All threads are cloned */
		livedump_set_stage(dump, LIVEDUMP_PERFORM_DUMP);
		livedump_signal_leader(dump->dumped_leader);

		wait_for_completion(&dump->dump_complete);
		ret = livedump_status(dump);
	}

	put_dump(dump);

	return ret;

out_err:
	kfree(dump);
	return ret;
}

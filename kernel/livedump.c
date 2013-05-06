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
 * task leader being cloned, t is a thread being cloned, C is the clone
 * leader and c is a clone thread.
 *
 *
 * O: allocate dump
 * O: T->dump = dump
 * O: signal(T)
 * O: wait for dump_ready
 * T: C = clone(T)
 * T: for each (t) t->dump = dump, signal(t)
 * T: wait for mm cloned
 * t: c = clone(c)
 * t: if (I am last clone) signal(C)
 * t: wait for mm cloned
 * C: C->mm = clone mm
 * C: wake O with dump_ready
 * O: set mm cloned
 * O: wait for dump_complete
 * C: for each (c) c->mm = cloned mm
 * C: dump core
 * C: wake O with dump_complete
 * C: exit
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/file.h>
#include <linux/err.h>
#include <linux/binfmts.h>
#include <linux/mutex.h>
#include <linux/livedump.h>
#include <linux/ioprio.h>
#include <linux/coredump.h>

#include <asm/mmu_context.h>
#include <asm/processor.h>

int livedump_take(struct livedump_context *dump)
{
	int status;

	/* Initialize the rest of livedump context. */
	livedump_set_status(dump, 0);
	livedump_stage(dump, COPY_LEADER);
	init_completion(&dump->dump_complete);
	init_completion(&dump->dump_ready);

	/* Kref is 1, so don't use get_dump(). */
	dump->origin->dump = dump;
	/* Signal the group leader to clone, thus starting the dump. */
	livedump_request(dump->origin);

	wait_for_completion(&dump->dump_ready);
	status = livedump_status(dump);
	if (unlikely(status)) {
		/* There was error cloning leader. */
		if (!dump->leader) {
			dump->origin->dump = NULL;
			put_dump(dump);
		}
		return status;
	}

	wait_for_completion(&dump->dump_complete);
	return livedump_status(dump);
}

/*
 * Copy current task_struct, make clone suitable for dumping.
 */
static struct task_struct *livedump_clone(struct livedump_param *param,
					  unsigned long clone_flags)
{
	/* We use the same pid as the cloned thread. */
	struct pid *pid = get_task_pid(current, PIDTYPE_PID);
	struct pt_regs regs;
	struct task_struct *clone;
	int err, prio;

	regs = *task_pt_regs(current);
	clone = copy_process(CLONE_LIVEDUMP | clone_flags,
			     KSTK_ESP(current), 0, NULL, pid, 0, 0);
	if (unlikely(IS_ERR(clone))) {
		put_pid(pid);
		return clone;
	}

	__set_task_state(clone, TASK_STOPPED);

	/* FIXME - do we need this on every thread or just the leader? */
	set_user_nice(clone, param->sched_nice);

	/* Clone will have inherited I/O scheduling class, but new priority. */
	prio = get_task_ioprio(clone);
	if (prio < 0) {
		put_pid(pid);
		return ERR_PTR(prio);
	}
	err = set_task_ioprio(clone, IOPRIO_PRIO_VALUE
			      (IOPRIO_PRIO_CLASS(prio), param->io_prio));
	if (err) {
		put_pid(pid);
		return ERR_PTR(err);
	}

	clone->signal->oom_score_adj = param->oom_adj;

	/* This is for the leader only, as sys_setrlimit() does. */
	if (!(clone_flags & CLONE_THREAD) && param->core_limit) {
		clone->signal->rlim[RLIMIT_CORE].rlim_cur = param->core_limit;
		clone->signal->rlim[RLIMIT_CORE].rlim_max = param->core_limit;
	}

	return clone;
}

/*
 * Clone the thread group leader. If we have more than one
 * thread in this group, ask other threads to clone themselves.
 * Otherwise, asking the leader's clone to perform the dump.
 */
void livedump_clone_leader(void)
{
	struct livedump_context *dump;
	struct task_struct *p, *clone;
	int nr_dump_threads = 0;

	dump = current->dump;
	BUG_ON(!dump);

	clone = livedump_clone(&dump->param, CLONE_PARENT);
	if (unlikely(IS_ERR(clone))) {
		livedump_set_status(dump, PTR_ERR(clone));
		complete_all(&dump->dump_ready);
		return;
	}

	clone->dump = get_dump(dump);

	/* siglock protects the thread list. */
	spin_lock_irq(&current->sighand->siglock);
	for (p = next_thread(current); p != current; p = next_thread(p))
		nr_dump_threads++;

	if (nr_dump_threads > 0) {
		atomic_set(&dump->nr_clone_remains, nr_dump_threads);
		livedump_stage(dump, COPY_THREADS);
		dump->leader = clone;
		for (p = next_thread(current); p != current;
		     p = next_thread(p)) {
			p->dump = get_dump(dump);
			__livedump_request(p);
		}
	} else {
		livedump_stage(dump, PERFORM_DUMP);
		/* Note: locking validator may warn about recursive locking
		   since we're asking for the nested lock clone->sighand->siglock,
		   which is of the same class as current->sighand->siglock. */
		livedump_request(clone);
	}
	spin_unlock_irq(&current->sighand->siglock);
	livedump_wait(dump);
}

/*
 * Clone one thread, force the new thread group leader
 * to perform the dump if we're the last thread cloned.
 */
void livedump_clone_thread(void)
{
	struct livedump_context *dump;
	struct task_struct *clone;

	dump = current->dump;
	BUG_ON(!dump);

	/*
	 * For non-leader threads, make sure we clone the signal stuff
	 * from the cloned leader thread.  Important to keep the thread
	 * list signal lock the same for all threads.
	 */
	clone = livedump_clone(&dump->param, CLONE_THREAD | CLONE_SIGHAND);
	if (unlikely(IS_ERR(clone))) {
		/*
		 * Save first error we've encountered. Other threads
		 * may have failed to clone themselves too, but their
		 * errors will be discarded.
		 */
		if (!livedump_status(dump))
			livedump_set_status(dump, PTR_ERR(clone));
	}
	if (atomic_dec_and_test(&dump->nr_clone_remains)) {
		/* All threads are cloned, or at least have tried to clone. */
		livedump_stage(dump, PERFORM_DUMP);
		livedump_request(dump->leader);
	}
	livedump_wait(dump);
}

/*
 * Copy the mm from the original thread group to the clone group.
 */
static long livedump_copy_context(void)
{
	struct mm_struct *newmm, *oldmm;
	struct task_struct *p = current;
	struct livedump_context *dump = p->dump;

	BUG_ON(!dump);
	BUG_ON(!dump->origin);
	BUG_ON(p->mm != p->active_mm);

	/*
	 * All original threads are blocked on dump->dump_ready, so it
	 * should be safe to duplicate mm and other important things
	 * from them.
	 */
	newmm = dup_mm(dump->origin);
	if (unlikely(!newmm))
		return -ENOMEM;

	/* MM is copied, we can now let the original threads go. */
	complete_all(&dump->dump_ready);

	/* FIXME - refcounts on oldmm? */
	oldmm = p->active_mm;
	p->mm = p->active_mm = newmm;
	preempt_disable();
	activate_mm(oldmm, newmm);
	preempt_enable();
	mmput(oldmm);

	for (p = next_thread(p); p != current; p = next_thread(p)) {
		mmput(p->mm);
		p->mm = p->active_mm = newmm;
		atomic_inc(&newmm->mm_users);
#ifdef CONFIG_PREEMPT
		/*
		 * Restore original preempt count just to allow
		 * correct exit for this clone.
		 */
		init_task_preempt_count(p);
#endif
	}
	return 0;
}

/*
 * Complete the dump. Core file is dumped only if dump->status is 0
 * before dumping, i.e. there was no errors on the previous stages.
 */
void livedump_perform_dump(siginfo_t *info)
{
	struct livedump_context *dump = current->dump;
	sigset_t blocked;
	long status;

	BUG_ON(!dump);
	current->flags |= PF_SIGNALED;

	status = livedump_status(dump);
	if (!status)
		/* There was no errors. Try to copy mm and other
		   substantial stuff, and allow original threads
		   to run in case of success. */
		status = livedump_copy_context();
	if (status) {
		/* There was some error, while copying mm or earlier.
		   Allow original threads to run, but do not dump core. */
		complete_all(&dump->dump_ready);
		goto exiting;
	}

	/*
	 * Everything looks valid, may dump core. All signals are
	 * blocked to avoid magic -ERESTARTSYS errors comes due to I/O
	 * via NFS.
	 */
	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);

	status = do_coredump(info);

exiting:
	livedump_set_status(dump, status);
	complete_all(&dump->dump_complete);
	do_group_exit(SIGKILL);
	/* NOTREACHED */
}

void livedump_ref_done(struct kref *ref)
{
	kfree(container_of(ref, struct livedump_context, ref));
}

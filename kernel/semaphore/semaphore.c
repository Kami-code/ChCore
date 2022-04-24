#include <semaphore/semaphore.h>
#include <sched/sched.h>
#include <object/thread.h>
#include <sched/context.h>
#include <irq/irq.h>

void init_sem(struct semaphore *sem)
{
        sem->sem_count = 0;
        sem->waiting_threads_count = 0;
        init_list_head(&sem->waiting_threads);
}

/*
 * Lab4
 * Return 0 if wait successfully, -EAGAIN otherwise
 * Hint: use sched() and eret_to_thread if current thread should be blocked.
 * You should also update the state of current thread to TS_WAITING
 * and set the return value of the current thread.
 * Besides, you should `obj_put` the sem before eret to the new thread.
 */
s32 wait_sem(struct semaphore *sem, bool is_block)
{
        s32 ret = 0;
        /* LAB 4 TODO BEGIN */
        if (current_thread == NULL) {
        	return -EAGAIN;
        }
        printk("in wait_sem sem->count = %d, is_block = %d, current_thread = %d\n", sem->sem_count, is_block, current_thread);
	if (sem->sem_count == 0) {
		if (is_block == 1) {
			list_append(&current_thread->sem_queue_node, &sem->waiting_threads);
			
			current_thread->thread_ctx->state = TS_WAITING;
			//struct thread * thread = rr_sched_choose_thread();
			obj_put(sem);
			rr_top();
			sys_yield();
			sched();
			//printk("after_eret_to_thread thread = %d\n", thread);
			eret_to_thread(switch_context());
			
			return -EAGAIN;
		}
		else {
			return -EAGAIN;
		}
	}
	else {
		sem->sem_count -= 1;
	}
        /* LAB 4 TODO END */
        return ret;
}

/*
 * Lab4
 * Return 0 if signal successfully
 * Hint: use `list_entry` to find the wakeup target in the waiting_threads list
 * Remember to delete the thread from the list using `list_del`.
 * Enqueue it to the ready queue rather than directly switch to it.
 */
s32 signal_sem(struct semaphore *sem)
{
        /* LAB 4 TODO BEGIN */
        struct thread *thread = NULL;
        if (list_empty(&sem->waiting_threads))
	{
		sem->sem_count += 1;
		return 0;
	}
	else {
		thread = list_entry(sem->waiting_threads.next, struct thread, sem_queue_node);
		list_del(sem->waiting_threads.next);
		rr_sched_enqueue(thread);
	}
        /* LAB 4 TODO END */
        return 0;
}

s32 sys_create_sem(void)
{
        struct semaphore *sem = NULL;
        int sem_cap = 0;
        int ret = 0;

        sem = obj_alloc(TYPE_SEMAPHORE, sizeof(*sem));
        if (!sem) {
                ret = -ENOMEM;
                goto out_fail;
        }
        init_sem(sem);

        sem_cap = cap_alloc(current_cap_group, sem, 0);
        if (sem_cap < 0) {
                ret = sem_cap;
                goto out_free_obj;
        }

        return sem_cap;
out_free_obj:
        obj_free(sem);
out_fail:
        return ret;
}

s32 sys_wait_sem(u32 sem_cap, bool is_block)
{
        struct semaphore *sem = NULL;
        int ret;

        sem = obj_get(current_thread->cap_group, sem_cap, TYPE_SEMAPHORE);
        if (!sem) {
                ret = -ECAPBILITY;
                goto out;
        }
        ret = wait_sem(sem, is_block);
        obj_put(sem);
out:
        return ret;
}

s32 sys_signal_sem(u32 sem_cap)
{
        struct semaphore *sem = NULL;
        int ret;
        sem = obj_get(current_thread->cap_group, sem_cap, TYPE_SEMAPHORE);
        if (!sem) {
                ret = -ECAPBILITY;
                goto out;
        }
        ret = signal_sem(sem);
        obj_put(sem);
out:
        return ret;
}

/*
pt_regs structure definition for reference:

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
#ifdef __AARCH64EB__
	u32 unused2;
	s32 syscallno;
#else
	s32 syscallno;
	u32 unused2;
#endif

	u64 orig_addr_limit;
	// Only valid when ARM64_HAS_IRQ_PRIO_MASKING is enabled.
	u64 pmr_save;
	u64 stackframe[2];
};
*/

#define TRACY_REGS_NAME user_pt_regs

#define TRACY_SYSCALL_OPSIZE 8

/* ARM64 puts syscall number into X8 */
#define TRACY_SYSCALL_REGISTER regs[8]
#define TRACY_SYSCALL_N regs[8]

/* Return code is X0 */
#define TRACY_RETURN_CODE regs[0]

#define TRACY_IP_REG pc

#define TRACY_STACK_POINTER sp

#define TRACY_NR_MMAP __NR_mmap2
#define __NR_vfork 1071

/* Register used to pass trampy code the tracer PID */
#define TRAMPY_PID_REG regs[4]
#define TRAMPY_PID_ARG a4

#define TRACY_ABI_COUNT 1

#define TRACY_ABI_EABI 0

#define TRACY_ABI_NATIVE TRACY_ABI_EABI

struct tracy_event;

int get_abi(struct tracy_event *s);
long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi);
long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val);

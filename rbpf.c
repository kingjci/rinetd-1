#include "rbpf.h"
#include<stdio.h>
#include<string.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

#define SLL_HDR_LEN	16		/* total header length */
#define MAXIMUM_SNAPLEN		262144
/*
 * This is for Linux cooked sockets.
 */
#define DLT_LINUX_SLL	113

static int fix_offset(struct bpf_insn *p);
static int fix_program(int fd, struct bpf_program *filter, struct sock_fprog *fcode, int is_mmapped);
static int set_kernel_filter(int fd, struct sock_fprog *fcode);

int pcap_compile_nopcap(int snaplen_arg, int linktype_arg,
		    struct bpf_program *program,
	     const char *buf, int optimize, bpf_u_int32 mask);

static struct sock_filter	total_insn
	= BPF_STMT(BPF_RET | BPF_K, 0);
static struct sock_fprog	total_fcode
	= { 1, &total_insn };

/*
 *  Attach the given BPF code to the packet capture device.
 */
static int
pcap_setfilter_linux_common(int fd, struct bpf_program *filter,
    int is_mmapped)
{
	struct sock_fprog	fcode;
	int			can_filter_in_kernel;
	int			err = 0;

	if (!filter) {
	    printf("setfilter: No filter specified");
		return -1;
	}

	/* Make our private copy of the filter */

	//if (install_bpf_program(handle, filter) < 0)
		/* install_bpf_program() filled in errbuf */
	//	return -1;

	/*
	 * Run user level packet filter by default. Will be overriden if
	 * installing a kernel filter succeeds.
	 */
	//handlep->filter_in_userland = 1;

	/* Install kernel level filter if possible */

#ifdef USHRT_MAX
	if (filter->bf_len > USHRT_MAX) {
		/*
		 * fcode.len is an unsigned short for current kernel.
		 * I have yet to see BPF-Code with that much
		 * instructions but still it is possible. So for the
		 * sake of correctness I added this check.
		 */
		fprintf(stderr, "Warning: Filter too complex for kernel\n");
		fcode.len = 0;
		fcode.filter = NULL;
		can_filter_in_kernel = 0;
	} else
#endif /* USHRT_MAX */
	{
		/*
		 * Oh joy, the Linux kernel uses struct sock_fprog instead
		 * of struct bpf_program and of course the length field is
		 * of different size. Pointed out by Sebastian
		 *
		 * Oh, and we also need to fix it up so that all "ret"
		 * instructions with non-zero operands have MAXIMUM_SNAPLEN
		 * as the operand if we're not capturing in memory-mapped
		 * mode, and so that, if we're in cooked mode, all memory-
		 * reference instructions use special magic offsets in
		 * references to the link-layer header and assume that the
		 * link-layer payload begins at 0; "fix_program()" will do
		 * that.
		 */
		switch (fix_program(fd, filter, &fcode, is_mmapped)) {

		case -1:
		default:
			/*
			 * Fatal error; just quit.
			 * (The "default" case shouldn't happen; we
			 * return -1 for that reason.)
			 */
			return -1;

		case 0:
			/*
			 * The program performed checks that we can't make
			 * work in the kernel.
			 */
			can_filter_in_kernel = 0;
			break;

		case 1:
			/*
			 * We have a filter that'll work in the kernel.
			 */
			can_filter_in_kernel = 1;
			break;
		}
	}

	/*
	 * NOTE: at this point, we've set both the "len" and "filter"
	 * fields of "fcode".  As of the 2.6.32.4 kernel, at least,
	 * those are the only members of the "sock_fprog" structure,
	 * so we initialize every member of that structure.
	 *
	 * If there is anything in "fcode" that is not initialized,
	 * it is either a field added in a later kernel, or it's
	 * padding.
	 *
	 * If a new field is added, this code needs to be updated
	 * to set it correctly.
	 *
	 * If there are no other fields, then:
	 *
	 *	if the Linux kernel looks at the padding, it's
	 *	buggy;
	 *
	 *	if the Linux kernel doesn't look at the padding,
	 *	then if some tool complains that we're passing
	 *	uninitialized data to the kernel, then the tool
	 *	is buggy and needs to understand that it's just
	 *	padding.
	 */
	if (can_filter_in_kernel) {
		if ((err = set_kernel_filter(fd, &fcode)) == 0)
		{
			/*
			 * Installation succeded - using kernel filter,
			 * so userland filtering not needed.
			 */
			//handlep->filter_in_userland = 0;
		}
		else if (err == -1)	/* Non-fatal error */
		{
			/*
			 * Print a warning if we weren't able to install
			 * the filter for a reason other than "this kernel
			 * isn't configured to support socket filters.
			 */
			if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) {
				fprintf(stderr,
				    "Warning: Kernel filter failed: %s\n",
					strerror(errno));
			}
		}
	}

	/*
	 * If we're not using the kernel filter, get rid of any kernel
	 * filter that might've been there before, e.g. because the
	 * previous filter could work in the kernel, or because some other
	 * code attached a filter to the socket by some means other than
	 * calling "pcap_setfilter()".  Otherwise, the kernel filter may
	 * filter out packets that would pass the new userland filter.
	 */
	//if (handlep->filter_in_userland) {
	//	if (reset_kernel_filter(handle) == -1) {
	//		pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	//		    "can't remove kernel filter: %s",
	//		    pcap_strerror(errno));
	//		err = -2;	/* fatal error */
	//	}
	//}

	/*
	 * Free up the copy of the filter that was made by "fix_program()".
	 */
	if (fcode.filter != NULL)
		free(fcode.filter);

	if (err == -2)
		/* Fatal error */
		return -1;

	return 0;
}

static int
pcap_setfilter_linux(int fd, struct bpf_program *filter)
{
	return pcap_setfilter_linux_common(fd, filter, 0);
}

static int
fix_program(int fd, struct bpf_program *filter, struct sock_fprog *fcode, int is_mmapped)
{
	size_t prog_size;
	register int i;
	register struct bpf_insn *p;
	struct bpf_insn *f;
	int len;

	/*
	 * Make a copy of the filter, and modify that copy if
	 * necessary.
	 */
	prog_size = sizeof(*filter->bf_insns) * filter->bf_len;
	len = filter->bf_len;
	f = (struct bpf_insn *)malloc(prog_size);
	if (f == NULL) {
		//pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		//	 "malloc: %s", pcap_strerror(errno));
		return -1;
	}
	memcpy(f, filter->bf_insns, prog_size);
	fcode->len = len;
	fcode->filter = (struct sock_filter *) f;

	for (i = 0; i < len; ++i) {
		p = &f[i];
		/*
		 * What type of instruction is this?
		 */
		switch (BPF_CLASS(p->code)) {

		case BPF_RET:
			/*
			 * It's a return instruction; are we capturing
			 * in memory-mapped mode?
			 */
			if (!is_mmapped) {
				/*
				 * No; is the snapshot length a constant,
				 * rather than the contents of the
				 * accumulator?
				 */
				if (BPF_MODE(p->code) == BPF_K) {
					/*
					 * Yes - if the value to be returned,
					 * i.e. the snapshot length, is
					 * anything other than 0, make it
					 * MAXIMUM_SNAPLEN, so that the packet
					 * is truncated by "recvfrom()",
					 * not by the filter.
					 *
					 * XXX - there's nothing we can
					 * easily do if it's getting the
					 * value from the accumulator; we'd
					 * have to insert code to force
					 * non-zero values to be
					 * MAXIMUM_SNAPLEN.
					 */
					if (p->k != 0)
						p->k = MAXIMUM_SNAPLEN;
				}
			}
			break;

		case BPF_LD:
		case BPF_LDX:
			/*
			 * It's a load instruction; is it loading
			 * from the packet?
			 */
			switch (BPF_MODE(p->code)) {

			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/*
				 * Yes; are we in cooked mode?
				 */
				//if (handlep->cooked) {
					/*
					 * Yes, so we need to fix this
					 * instruction.
					 */
					if (fix_offset(p) < 0) {
						/*
						 * We failed to do so.
						 * Return 0, so our caller
						 * knows to punt to userland.
						 */
						return 0;
					}
				//}
				break;
			}
			break;
		}
	}
	return 1;	/* we succeeded */
}

static int
fix_offset(struct bpf_insn *p)
{
	/*
	 * What's the offset?
	 */
	if (p->k >= SLL_HDR_LEN) {
		/*
		 * It's within the link-layer payload; that starts at an
		 * offset of 0, as far as the kernel packet filter is
		 * concerned, so subtract the length of the link-layer
		 * header.
		 */
		p->k -= SLL_HDR_LEN;
	} else if (p->k == 0) {
		/*
		 * It's the packet type field; map it to the special magic
		 * kernel offset for that field.
		 */
		p->k = SKF_AD_OFF + SKF_AD_PKTTYPE;
	} else if (p->k == 14) {
		/*
		 * It's the protocol field; map it to the special magic
		 * kernel offset for that field.
		 */
		p->k = SKF_AD_OFF + SKF_AD_PROTOCOL;
	} else if ((bpf_int32)(p->k) > 0) {
		/*
		 * It's within the header, but it's not one of those
		 * fields; we can't do that in the kernel, so punt
		 * to userland.
		 */
		return -1;
	}
	return 0;
}

static int
set_kernel_filter(int fd, struct sock_fprog *fcode)
{
	int total_filter_on = 0;
	int save_mode;
	int ret;
	int save_errno;

	/*
	 * The socket filter code doesn't discard all packets queued
	 * up on the socket when the filter is changed; this means
	 * that packets that don't match the new filter may show up
	 * after the new filter is put onto the socket, if those
	 * packets haven't yet been read.
	 *
	 * This means, for example, that if you do a tcpdump capture
	 * with a filter, the first few packets in the capture might
	 * be packets that wouldn't have passed the filter.
	 *
	 * We therefore discard all packets queued up on the socket
	 * when setting a kernel filter.  (This isn't an issue for
	 * userland filters, as the userland filtering is done after
	 * packets are queued up.)
	 *
	 * To flush those packets, we put the socket in read-only mode,
	 * and read packets from the socket until there are no more to
	 * read.
	 *
	 * In order to keep that from being an infinite loop - i.e.,
	 * to keep more packets from arriving while we're draining
	 * the queue - we put the "total filter", which is a filter
	 * that rejects all packets, onto the socket before draining
	 * the queue.
	 *
	 * This code deliberately ignores any errors, so that you may
	 * get bogus packets if an error occurs, rather than having
	 * the filtering done in userland even if it could have been
	 * done in the kernel.
	 */
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &total_fcode, sizeof(total_fcode)) == 0) {
		char drain[1];

		/*
		 * Note that we've put the total filter onto the socket.
		 */
		total_filter_on = 1;

		/*
		 * Save the socket's current mode, and put it in
		 * non-blocking mode; we drain it by reading packets
		 * until we get an error (which is normally a
		 * "nothing more to be read" error).
		 */
		save_mode = fcntl(fd, F_GETFL, 0);
		if (save_mode == -1) {
			    printf("can't get FD flags when changing filter: %s",
			    strerror(errno));
			return -2;
		}
		if (fcntl(fd, F_SETFL, save_mode | O_NONBLOCK) < 0) {
			    printf("can't set nonblocking mode when changing filter: %s",
			    strerror(errno));
			return -2;
		}
		while (recv(fd, &drain, sizeof drain, MSG_TRUNC) >= 0)
			;
		save_errno = errno;
		if (save_errno != EAGAIN) {
			/*
			 * Fatal error.
			 *
			 * If we can't restore the mode or reset the
			 * kernel filter, there's nothing we can do.
			 */
			(void)fcntl(fd, F_SETFL, save_mode);
			//(void)reset_kernel_filter(handle);
			    printf("recv failed when changing filter: %s",
			    strerror(save_errno));
			return -2;
		}
		if (fcntl(fd, F_SETFL, save_mode) == -1) {
			    printf("can't restore FD flags when changing filter: %s",
			    strerror(save_errno));
			return -2;
		}
	}

	/*
	 * Now attach the new filter.
	 */
	ret = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
			 fcode, sizeof(*fcode));
	if (ret == -1 && total_filter_on) {
		/*
		 * Well, we couldn't set that filter on the socket,
		 * but we could set the total filter on the socket.
		 *
		 * This could, for example, mean that the filter was
		 * too big to put into the kernel, so we'll have to
		 * filter in userland; in any case, we'll be doing
		 * filtering in userland, so we need to remove the
		 * total filter so we see packets.
		 */
		save_errno = errno;

		/*
		 * If this fails, we're really screwed; we have the
		 * total filter on the socket, and it won't come off.
		 * Report it as a fatal error.
		 */
		//if (reset_kernel_filter(handle) == -1) {
			    printf("can't remove kernel total filter: %s",
			    strerror(errno));
			return -2;	/* fatal error */
		//}

		errno = save_errno;
	}
	return ret;
}

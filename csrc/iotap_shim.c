/*
 * Flattens the libproc structures iotap needs but the Rust libc crate does not define
 * (vnode_fdinfowithpath, socket_fdinfo, proc_vnodepathinfo). Every function returns 0 on
 * success or an errno value.
 */
#include <errno.h>
#include <libproc.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/un.h>

#define IOTAP_PATH_LEN 105 /* sun_path (104) plus a terminator */

struct iotap_sock {
	int32_t family;
	int32_t type;
	int32_t protocol;
	int32_t kind;      /* SOCKINFO_* */
	int32_t tcp_state; /* TSI_S_*, or -1 when not TCP */
	int32_t is_v4;     /* inet sockets: addresses hold IPv4 in their first four bytes */
	uint16_t lport;    /* host byte order */
	uint16_t rport;
	uint8_t laddr[16];
	uint8_t raddr[16];
	char local_path[IOTAP_PATH_LEN];
	char peer_path[IOTAP_PATH_LEN];
};

size_t
iotap_sock_size(void)
{
	return sizeof(struct iotap_sock);
}

static int
failure(void)
{
	return errno != 0 ? errno : ESRCH;
}

int
iotap_fd_path(int pid, int fd, char *buf, size_t len)
{
	struct vnode_fdinfowithpath info;

	if (buf == NULL || len == 0) {
		return EINVAL;
	}
	errno = 0;
	int n = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &info, (int)sizeof(info));
	if (n <= 0) {
		return failure();
	}
	if (n < (int)sizeof(info)) {
		return EIO;
	}
	strlcpy(buf, info.pvip.vip_path, len);
	return 0;
}

static void
copy_sun_path(char dst[IOTAP_PATH_LEN], const struct sockaddr_un *sun)
{
	size_t len = 0;

	if (sun->sun_len > offsetof(struct sockaddr_un, sun_path)) {
		len = sun->sun_len - offsetof(struct sockaddr_un, sun_path);
	}
	if (len > sizeof(sun->sun_path)) {
		len = sizeof(sun->sun_path);
	}
	len = strnlen(sun->sun_path, len);
	memcpy(dst, sun->sun_path, len);
	dst[len] = '\0';
}

int
iotap_fd_socket(int pid, int fd, struct iotap_sock *out)
{
	struct socket_fdinfo info;

	if (out == NULL) {
		return EINVAL;
	}
	memset(out, 0, sizeof(*out));
	out->tcp_state = -1;
	errno = 0;
	int n = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, (int)sizeof(info));
	if (n <= 0) {
		return failure();
	}
	if (n < (int)sizeof(info)) {
		return EIO;
	}

	const struct socket_info *si = &info.psi;
	out->family = si->soi_family;
	out->type = si->soi_type;
	out->protocol = si->soi_protocol;
	out->kind = si->soi_kind;

	const struct in_sockinfo *in = NULL;
	if (si->soi_kind == SOCKINFO_TCP) {
		in = &si->soi_proto.pri_tcp.tcpsi_ini;
		out->tcp_state = si->soi_proto.pri_tcp.tcpsi_state;
	} else if (si->soi_kind == SOCKINFO_IN) {
		in = &si->soi_proto.pri_in;
	}

	if (in != NULL) {
		/* Ports are stored in network byte order inside an int. */
		out->lport = ntohs((uint16_t)in->insi_lport);
		out->rport = ntohs((uint16_t)in->insi_fport);
		if (in->insi_vflag & INI_IPV4) {
			out->is_v4 = 1;
			memcpy(out->laddr, &in->insi_laddr.ina_46.i46a_addr4, 4);
			memcpy(out->raddr, &in->insi_faddr.ina_46.i46a_addr4, 4);
		} else {
			memcpy(out->laddr, &in->insi_laddr.ina_6, 16);
			memcpy(out->raddr, &in->insi_faddr.ina_6, 16);
		}
	} else if (si->soi_kind == SOCKINFO_UN) {
		copy_sun_path(out->local_path, &si->soi_proto.pri_un.unsi_addr.ua_sun);
		copy_sun_path(out->peer_path, &si->soi_proto.pri_un.unsi_caddr.ua_sun);
	}
	return 0;
}

int
iotap_proc_cwd(int pid, char *buf, size_t len)
{
	struct proc_vnodepathinfo info;

	if (buf == NULL || len == 0) {
		return EINVAL;
	}
	errno = 0;
	int n = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, (int)sizeof(info));
	if (n <= 0) {
		return failure();
	}
	if (n < (int)sizeof(info)) {
		return EIO;
	}
	strlcpy(buf, info.pvi_cdir.vip_path, len);
	return 0;
}

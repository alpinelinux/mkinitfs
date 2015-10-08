
/*
 * Copy me if you can.
 * by 20h
 *
 * Copyright (c) 2015 Natanael Copa <ncopa@alpinelinux.org>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <linux/netlink.h>

#include <libkmod.h>
#include <blkid.h>

#include "arg.h"

#define EVENT_TIMEOUT 2000

#define FOUND_DEVICE	0x1
#define FOUND_BOOTREPO	0x2
#define FOUND_APKOVL	0x4

static int dodebug;
char *argv0;

#if defined(DEBUG)
#include <stdarg.h>
static void dbg(const char *fmt, ...)
{
	va_list fmtargs;
	if (!dodebug)
		return;

	fprintf(stderr, "%s: ", argv0);
	va_start(fmtargs, fmt);
	vfprintf(stderr, fmt, fmtargs);
	va_end(fmtargs);
	fprintf(stderr, "\n");
}
#else
#define dbg(...)
#endif

struct uevent {
	char *buf;
	size_t bufsize;
	char *message;
	char *subsystem;
	char *action;
	char *modalias;
	char *devname;
	char *major;
	char *minor;
	char devnode[256];
};

struct ueventconf {
	char **program_argv;
	char *search_device;
	char *crypt_device;
	char *crypt_name;
	char *subsystem_filter;
	int modalias_count;
	int fork_count;
	char *bootrepos;
	char *apkovls;
};


static void sighandler(int sig)
{
	switch(sig) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGABRT:
	case SIGTERM:
		exit(0);
		break;
	default:
		break;
	}
}

static void initsignals(void)
{
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGABRT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, SIG_IGN);
}

static int init_netlink_socket(void)
{
	struct sockaddr_nl nls;
	int fd, slen;

	memset(&nls, 0, sizeof(nls));
	nls.nl_family = AF_NETLINK;
	nls.nl_pid = getpid();
	nls.nl_groups = -1;

	fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		    NETLINK_KOBJECT_UEVENT);
	if (fd < 0)
		err(1, "socket");

	/* kernel will not create events bigger than 16kb, but we need
	   buffer up all events during coldplug */
	slen = 512*1024;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &slen,
				sizeof(slen)) < 0) {
		err(1, "setsockopt");
	}
	slen = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &slen,
				sizeof(slen)) < 0) {
		err(1, "setsockopt");
	}

	if (bind(fd, (void *)&nls, sizeof(nls)))
		err(1, "bind");

	return fd;
}

void run_child(char **argv)
{
	pid_t pid;

	if (!(pid = fork())) {
		dbg("running %s", argv[0]);
		if (execv(argv[0], argv) < 0)
			err(1, argv[0]);
		exit(0);
	}
	if (pid < 0)
		err(1,"fork");

	waitpid(pid, NULL, 0);
}


int load_kmod(const char *modalias)
{
	static struct kmod_ctx *ctx = NULL;
	struct kmod_list *list = NULL;
	struct kmod_list *node;
	int r, count=0;

	if (ctx == NULL) {
		dbg("initializing kmod");
		ctx = kmod_new(NULL, NULL);
		if (ctx == NULL)
			return -1;
		kmod_set_log_fn(ctx, NULL, NULL);
		r = kmod_load_resources(ctx);
	}

	r = kmod_module_new_from_lookup(ctx, modalias, &list);
	if (r < 0) {
		dbg("alias '%s' lookup failure", modalias);
		return r;
	}

	kmod_list_foreach(node, list) {
		struct kmod_module *mod = kmod_module_get_module(node);
		const char *fmt;
		r = kmod_module_probe_insert_module(mod,
						    KMOD_PROBE_APPLY_BLACKLIST,
						    NULL, NULL, NULL, NULL);
		if (r == 0) {
			fmt = "module '%s' inserted";
			count++;
		} else if (r == KMOD_PROBE_APPLY_BLACKLIST) {
			fmt = "module '%s' is blacklisted";
		} else {
			fmt = "module '%s' failed";
		}
		dbg(fmt, kmod_module_get_name(mod));
		kmod_module_unref(mod);
	}
	kmod_module_unref_list(list);
	return count;
}

void start_mdadm(char *devnode)
{
	char *mdadm_argv[] = {
		"/sbin/mdadm",
		"--incremental",
		"--quiet",
		devnode,
		NULL
	};
	run_child(mdadm_argv);
}

void start_lvm2(char *devnode)
{
	char *lvm2_argv[] = {
		"/sbin/lvm", "vgchange",
		"--activate" , "ay", "--noudevsync", "--sysinit",
		NULL
	};
	run_child(lvm2_argv);
}

void start_cryptsetup(char *devnode, char *cryptdm)
{
	char *cryptsetup_argv[] = {
		"/sbin/cryptsetup", "luksOpen",
		devnode, cryptdm ? cryptdm : "crypdm", NULL
	};
	load_kmod("dm-crypt");
	run_child(cryptsetup_argv);
}

static int is_mounted(const char *devnode) {
	char line[PATH_MAX];
	FILE *f = fopen("/proc/mounts", "r");
	int r = 0;
	if (f == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		strtok(line, " ");
		if (strcmp(devnode, line) == 0) {
			r = 1;
			break;
		}
	}
	fclose(f);
	return r;
}

struct recurse_opts {
	const char *searchname;
	void (*callback)(const char *, const void *);
	void *userdata;
};

void recurse_dir(const char *dir, struct recurse_opts *opts)
{
	DIR *d = opendir(dir);
	struct dirent *entry;

	if (d == NULL)
		return;

	while ((entry = readdir(d)) != NULL) {
		char path[PATH_MAX];
		struct stat st;

		/* d_type is not supported by all filesystems so we need
		   lstat */
		snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
		if (lstat(path, &st) < 0) {
			dbg("%s: %s", path, strerror(errno));
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			if (entry->d_name[0] == '.')
				continue;
		} else if (opts->searchname
			   && strcmp(entry->d_name, opts->searchname) != 0) {
			continue;
		}

		if (S_ISDIR(st.st_mode))
			recurse_dir(path, opts);
		else
			opts->callback(path, opts->userdata);
	}
	closedir(d);
}

struct bootrepos {
	char *outfile;
	int count;
};

void bootrepo_cb(const char *path, const void *data)
{
	struct bootrepos *repos = (struct bootrepos *)data;
	int fd = open(repos->outfile, O_WRONLY | O_CREAT | O_APPEND);
	if (fd == -1)
		err(1, "%s", repos->outfile);

	write(fd, path, strlen(path) - strlen("/.boot_repository"));
	write(fd, "\n", 1);
	close(fd);
	dbg("added boot repository %s to %s\n", path, repos->outfile);
	repos->count++;
}

static int find_apkovl(const char *dir, const char *outfile)
{
	char pattern[PATH_MAX];
	glob_t gl;
	int r, fd;

	if (outfile == NULL)
		return 0;

	snprintf(pattern, sizeof(pattern), "%s/*.apkovl.tar.gz*", dir);

	r = glob(pattern, 0, NULL, &gl);
	if (r != 0)
		return 0;

	fd = open(outfile, O_WRONLY | O_CREAT | O_APPEND);
	if (fd == -1)
		err(1, "%s", outfile);

	for (r = 0; r < gl.gl_pathc; r++) {
		dbg("Found apkovl: %s", gl.gl_pathv[r]);
		write(fd, gl.gl_pathv[r], strlen(gl.gl_pathv[r]));
		write(fd, "\n", 1);
	}
	close(fd);
	globfree(&gl);
	return FOUND_APKOVL;
}

static int find_bootrepos(const char *devnode, const char *type,
			 char *bootrepos, const char *apkovls)
{
	char mountdir[PATH_MAX] = "";
	char *devname;
	int r, rc = 0;
	struct bootrepos repos = {
		.outfile = bootrepos,
		.count = 0,
	};
	struct recurse_opts opts = {
		.searchname = ".boot_repository",
		.callback = bootrepo_cb,
		.userdata = &repos,
	};


	/* skip already mounted devices */
	if (is_mounted(devnode)) {
		dbg("%s is mounted (%s). skipping", devnode, type);
		return 0;
	}
	devname = strrchr(devnode, '/');

	if (devname)
		snprintf(mountdir, sizeof(mountdir), "/media%s", devname);

	dbg("mounting %s on %s. (%s)", devnode, mountdir, type);
	mkdir(mountdir, 0755);

	r = mount(devnode, mountdir, type, MS_RDONLY, NULL);
	if (r < 0) {
		dbg("Failed to mount %s on %s: %s",
		    devnode, mountdir, strerror(errno));
		return 0;
	}

	recurse_dir(mountdir, &opts);
	if (repos.count > 0)
		rc |= FOUND_BOOTREPO;

	if (find_apkovl(mountdir, apkovls))
		rc |= FOUND_APKOVL;

	if (rc == 0)
		umount(mountdir);

	return rc;
}

int searchdev(char *devname, const char *searchdev, char *bootrepos,
	      const char *apkovls)
{
	static blkid_cache cache = NULL;
	char *type = NULL, *label = NULL, *uuid = NULL;
	char devnode[256];
	int rc = 0;

	if (searchdev == NULL && bootrepos == NULL && apkovls == NULL)
		return 0;

	if (searchdev && strcmp(devname, searchdev) == 0) {
		return FOUND_DEVICE;
	}

	if (cache == NULL)
		blkid_get_cache(&cache, NULL);

	snprintf(devnode, sizeof(devnode), "/dev/%s", devname);
	type = blkid_get_tag_value(cache, "TYPE", devnode);

	if (searchdev != NULL) {
		if (strncmp("LABEL=", searchdev, 6) == 0) {
			label = blkid_get_tag_value(cache, "LABEL", devnode);
			if (label && strcmp(label, searchdev+6) == 0)
				rc = FOUND_DEVICE;
		} else if (strncmp("UUID=", searchdev, 5) == 0) {
			uuid = blkid_get_tag_value(cache, "UUID", devnode);
			if (uuid && strcmp(uuid, searchdev+5) == 0)
				rc = FOUND_DEVICE;
		}
	}

	if (type || label || uuid) {
		dbg("%s:\n"
			"\ttype='%s'\n"
			"\tlabel='%s'\n"
			"\tuuid='%s'\n", devnode,
			type ? type : NULL,
			label ? label : NULL,
			uuid ? uuid : NULL);
	}

	if (!rc && type) {
		if (strcmp("linux_raid_member", type) == 0) {
			start_mdadm(devnode);
		} else if (strcmp("LVM2_member", type) == 0) {
			start_lvm2(devnode);
		} else if (bootrepos) {
			rc = find_bootrepos(devnode, type, bootrepos, apkovls);
		}
	}

	if (type)
		free(type);
	if (label)
		free(label);
	if (uuid)
		free(uuid);

	return rc;
}

int dispatch_uevent(struct uevent *ev, struct ueventconf *conf)
{
	if (conf->subsystem_filter && ev->subsystem
	    && strcmp(ev->subsystem, conf->subsystem_filter) != 0) {
		dbg("subsystem '%s' filtered out (by '%s').",
		    ev->subsystem, conf->subsystem_filter);
		return 0;
	}

	if (ev->action == NULL)
		return 0;

	if (ev->modalias != NULL && strcmp(ev->action, "add") == 0) {
		load_kmod(ev->modalias);
		conf->modalias_count++;

	} else if (ev->devname != NULL) {
		if (conf->program_argv[0] != NULL) {
			run_child(conf->program_argv);
			conf->fork_count++;
		}

		if (ev->subsystem && strcmp(ev->subsystem, "block") == 0
		    && strcmp(ev->action, "add") == 0) {
			int rc;

			snprintf(ev->devnode, sizeof(ev->devnode), "/dev/%s",
				 ev->devname);
			rc = searchdev(ev->devname, conf->search_device,
				       conf->bootrepos, conf->apkovls);
			if (rc)
				return rc;

			if (searchdev(ev->devname, conf->crypt_device, NULL,
				      NULL))
				start_cryptsetup(ev->devnode, conf->crypt_name);
		}
	}
	return 0;
}

int process_uevent(char *buf, const size_t len, struct ueventconf *conf)
{
	struct uevent ev;

	int i, slen = 0;
	char *key, *value;

	memset(&ev, 0, sizeof(ev));
	ev.buf = buf;
	ev.bufsize = len;
	clearenv();
	setenv("PATH", "/sbin:/bin", 1);

	for (i = 0; i < len; i += slen + 1) {

		key = buf + i;
		value = strchr(key, '=');
		slen = strlen(buf+i);

		if (i == 0 && slen != 0) {
			/* first line, the message */
			ev.message = key;
			continue;
		}

		if (!slen)
			continue;

		value[0] = '\0';
		value++;

		if (strcmp(key, "MODALIAS") == 0) {
			ev.modalias = value;
		} else if (strcmp(key, "ACTION") == 0) {
			ev.action = value;
		} else if (strcmp(key, "SUBSYSTEM") == 0) {
			ev.subsystem = value;
		} else if (strcmp(key, "DEVNAME") == 0) {
			ev.devname = value;
		} else if (strcmp(key, "MAJOR") == 0) {
			ev.major = value;
		} else if (strcmp(key, "MINOR") == 0) {
			ev.minor = value;
		}

		if (strcmp(key, "PATH")) {
			setenv(key, value, 1);
		}
	}
	return dispatch_uevent(&ev, conf);
}

void trigger_uevent_cb(const char *path, const void *data)
{
	int fd = open(path, O_WRONLY);
	write(fd, "add", 3);
	close(fd);
}

void *trigger_thread(void *data)
{
	int fd = *(int *)data;
	uint64_t ok = 1;
	struct recurse_opts opts = {
		.searchname = "uevent",
		.callback = trigger_uevent_cb,
		.userdata = NULL,
	};
	recurse_dir("/sys/bus", &opts);
	recurse_dir("/sys/devices", &opts);
	write(fd, &ok, sizeof(ok));
	return NULL;
}

void usage(int rc)
{
	printf("coldplug system til given device is found\n"
	"usage: %s [options] DEVICE\n"
	"\n"
	"options:\n"
	" -a OUTFILE      add paths to found apkovls to OUTFILE\n"
	" -b OUTFILE      add found boot repositories to OUTFILE\n"
	" -c CRYPTDEVICE  run cryptsetup luksOpen when CRYPTDEVICE is found\n"
	" -h              show this help\n"
	" -m CRYPTNAME    use CRYPTNAME name for crypto device mapping\n"
	" -d              enable debugging ouput\n"
	" -f SUBSYSTEM    filter subsystem\n"
	" -p PROGRAM      use PROGRAM as handler for every event with DEVNAME\n"
	"\n", argv0);

	exit(rc);
}

int main(int argc, char *argv[])
{
	struct pollfd fds[2];
	int numfds = 2;
	int r;
	struct ueventconf conf;
	int event_count = 0;
	size_t total_bytes;
	int ret = 1, found = 0;
	char *program_argv[2] = {0,0};
	pthread_t tid;

	memset(&conf, 0, sizeof(conf));
	conf.program_argv = program_argv;
	argv0 = strrchr(argv[0], '/');
	if (argv0++ == NULL)
		argv0 = argv[0];

	ARGBEGIN {
	case 'a':
		conf.apkovls = EARGF(usage(1));;
		break;
	case 'b':
		conf.bootrepos = EARGF(usage(1));
		break;
	case 'c':
		conf.crypt_device = EARGF(usage(1));
		break;
	case 'h':
		usage(0);
		break;
	case 'm':
		conf.crypt_name = EARGF(usage(1));
		break;
	case 'd':
		dodebug = 1;
		break;
	case 'f':
		conf.subsystem_filter = EARGF(usage(1));
		break;
	case 'p':
		conf.program_argv[0] = EARGF(usage(1));
		break;
	default:
		usage(1);
	} ARGEND;

	if (argc > 0)
		conf.search_device = argv[0];

	initsignals();

	fds[0].fd = init_netlink_socket();
	fds[0].events = POLLIN;

	fds[1].fd = eventfd(0, EFD_CLOEXEC);
	fds[1].events = POLLIN;

	pthread_create(&tid, NULL, trigger_thread, &fds[1].fd);

	while ((r = poll(fds, numfds, EVENT_TIMEOUT)) > 0) {
		size_t len;
		struct iovec iov;
		char cbuf[CMSG_SPACE(sizeof(struct ucred))];
		char buf[16384];
		struct cmsghdr *chdr;
		struct ucred *cred;
		struct msghdr hdr;
		struct sockaddr_nl cnls;

		if (numfds > 1 && fds[1].revents & POLLIN) {
			close(fds[1].fd);
			fds[1].fd = -1;
			numfds--;
			pthread_join(tid, NULL);
		}

		if (!(fds[0].revents & POLLIN))
			continue;

		iov.iov_base = &buf;
		iov.iov_len = sizeof(buf);
		memset(&hdr, 0, sizeof(hdr));
		hdr.msg_iov = &iov;
		hdr.msg_iovlen = 1;
		hdr.msg_control = cbuf;
		hdr.msg_controllen = sizeof(cbuf);
		hdr.msg_name = &cnls;
		hdr.msg_namelen = sizeof(cnls);

		len = recvmsg(fds[0].fd, &hdr, 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			err(1, "recvmsg");
		}
		if (len < 32 || len >= sizeof(buf))
			continue;

		total_bytes += len;
		chdr = CMSG_FIRSTHDR(&hdr);
		if (chdr == NULL || chdr->cmsg_type != SCM_CREDENTIALS)
			continue;

		/* filter out messages that are not from root or kernel */
		cred = (struct ucred *)CMSG_DATA(chdr);
		if (cred->uid != 0 || cnls.nl_pid > 0)
			continue;

		event_count++;
		found |= process_uevent(buf, len, &conf);

		if ((found & FOUND_DEVICE)
		    || ((found & FOUND_BOOTREPO) && (found & FOUND_APKOVL))) {
			ret = 0;
			break;
		}

		if (fds[0].revents & POLLHUP) {
			dbg("parent hung up\n");
			break;
		}
	}
	if (r == -1)
		err(1, "poll");

	if (r == 0)
		dbg("exit due to timeout");
	dbg("modaliases: %i, forks: %i, events: %i, total bufsize: %zu",
		conf.modalias_count,
		conf.fork_count,
		event_count, total_bytes);

	return ret;
}



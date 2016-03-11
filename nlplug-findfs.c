
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
#include <termios.h>
#include <unistd.h>

#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <linux/netlink.h>

#include <libkmod.h>
#include <blkid.h>
#include <libcryptsetup.h>

#include "arg.h"

#define DEFAULT_EVENT_TIMEOUT	250
/* usb mass storage needs 1 sec to settle */
#define USB_STORAGE_TIMEOUT	1000

#define FOUND_DEVICE	0x1
#define FOUND_BOOTREPO	0x2
#define FOUND_APKOVL	0x4

#define TRIGGER_THREAD		0x1
#define CRYPTSETUP_THREAD	0x2

#define LVM_PATH	"/sbin/lvm"
#define MDADM_PATH	"/sbin/mdadm"

static int dodebug;
static char *default_envp[2];
char *argv0;
static int use_mdadm, use_lvm;

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

#define envcmp(env, key) (strncmp(env, key "=", strlen(key "=")) == 0)


static char **clone_array(char *const *const a)
{
	size_t i, s;
	char **c, *p;

	if (!a) return 0;

	s = sizeof(char*);
	for (i = 0; a[i]; i++)
		s += sizeof(char*) + strlen(a[i]) + 1;
	c = malloc(s);
	p = (char*)(c + i + 1);
	for (i = 0; a[i]; i++) {
		c[i] = p;
		p += sprintf(p, "%s", a[i]) + 1;
	}
	c[i] = 0;
	return c;
}

struct spawn_task {
	struct spawn_task *next;
	char **argv, **envp;
};
struct spawn_manager {
	int num_running;
	int max_running;
	struct spawn_task *first, *last;
};

static struct spawn_manager spawnmgr;

static void spawn_execute(struct spawn_manager *mgr, char **argv, char **envp)
{
	pid_t pid;

	dbg("[%d/%d] running %s", mgr->num_running+1, mgr->max_running, argv[0]);
	if (!(pid = fork())) {
		if (execve(argv[0], argv, envp ? envp : default_envp) < 0)
			err(1, argv[0]);
		exit(0);
	}
	if (pid < 0)
		err(1,"fork");

	mgr->num_running++;
}

static void spawn_queue(struct spawn_manager *mgr, char **argv, char **envp)
{
	struct spawn_task *task;

	task = malloc(sizeof *task);
	if (!task) return;
	*task = (struct spawn_task) {
		.next = NULL,
		.argv = clone_array(argv),
		.envp = clone_array(envp),
	};
	if (mgr->last) {
		mgr->last->next = task;
		mgr->last = task;
	} else {
		mgr->first = mgr->last = task;
	}
}

static void spawn_command(struct spawn_manager *mgr, char **argv, char **envp)
{
	if (!mgr->max_running)
		mgr->max_running = sysconf(_SC_NPROCESSORS_ONLN);
	if (mgr->num_running < mgr->max_running)
		spawn_execute(mgr, argv, envp);
	else
		spawn_queue(mgr, argv, envp);
}

static void spawn_reap(struct spawn_manager *mgr, pid_t pid)
{
	mgr->num_running--;
	if (mgr->first && mgr->num_running < mgr->max_running) {
		struct spawn_task *task = mgr->first;
		if (task->next)
			mgr->first = task->next;
		else
			mgr->first = mgr->last = NULL;
		spawn_execute(mgr, task->argv, task->envp);
		free(task->argv);
		free(task->envp);
		free(task);
	}
}

static int spawn_active(struct spawn_manager *mgr)
{
	return mgr->num_running || mgr->first;
}

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
	char *envp[64];
};

struct ueventconf {
	char **program_argv;
	char *search_device;
	char *crypt_device;
	char *crypt_name;
	char crypt_devnode[256];
	char *subsystem_filter;
	int modalias_count;
	int fork_count;
	char *bootrepos;
	char *apkovls;
	int timeout;
	int efd;
	unsigned running_threads;
	pthread_t cryptsetup_tid;
	pthread_mutex_t cryptsetup_mutex;
};


static void sighandler(int sig)
{
	switch (sig) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGABRT:
	case SIGTERM:
		exit(0);
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
	signal(SIGCHLD, sighandler);
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

static int load_kmod(const char *modalias, char *driver, size_t len)
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
		if (driver)
			strncpy(driver, kmod_module_get_name(mod), len);
		kmod_module_unref(mod);
	}
	kmod_module_unref_list(list);
	return count;
}

static void start_mdadm(char *devnode)
{
	char *mdadm_argv[] = {
		MDADM_PATH,
		"--incremental",
		"--quiet",
		devnode,
		NULL
	};
	if (use_mdadm)
		spawn_command(&spawnmgr, mdadm_argv, 0);
}

static void start_lvm2(char *devnode)
{
	char *lvm2_argv[] = {
		LVM_PATH, "vgchange",
		"--activate" , "ay", "--noudevsync", "--sysinit", "-q", "-q",
		NULL
	};
	if (use_lvm)
		spawn_command(&spawnmgr, lvm2_argv, 0);
}


static int read_pass(char *pass, size_t pass_size)
{
	struct termios old_flags, new_flags;
	int r;

	tcgetattr(STDIN_FILENO, &old_flags);
	new_flags = old_flags;
	new_flags.c_lflag &= ~ECHO;
	new_flags.c_lflag |= ECHONL;

	r = tcsetattr(STDIN_FILENO, TCSANOW, &new_flags);
	if (r < 0) {
		warn("tcsetattr");
		return r;
	}

	if (fgets(pass, pass_size, stdin) == NULL) {
		warn("fgets");
		return -1;
	}
	pass[strlen(pass) - 1] = '\0';

	if (tcsetattr(STDIN_FILENO, TCSANOW, &old_flags) < 0) {
		warn("tcsetattr");
		return r;
	}

	return 0;
}

static void *cryptsetup_thread(void *data)
{
	struct ueventconf *c = (struct ueventconf *)data;
	uint64_t ok = CRYPTSETUP_THREAD;
	struct crypt_device *cd;
	int r, passwd_tries = 5;

	r = crypt_init(&cd, c->crypt_devnode);
	if (r < 0) {
		warnx("crypt_init(%s)", c->crypt_devnode);
		goto notify_out;
	}

	r = crypt_load(cd , CRYPT_LUKS1, NULL);
	if (r < 0) {
		warnx("crypt_load(%s)", c->crypt_devnode);
		goto free_out;
	}

	while (passwd_tries > 0) {
		char pass[1024];

		printf("Enter passphrase for %s: ", c->crypt_devnode);
		fflush(stdout);

		if (read_pass(pass, sizeof(pass)) < 0)
			goto free_out;
		passwd_tries--;

		pthread_mutex_lock(&c->cryptsetup_mutex);
		r = crypt_activate_by_passphrase(cd, c->crypt_name,
						 CRYPT_ANY_SLOT,
						 pass, strlen(pass), 0);
		pthread_mutex_unlock(&c->cryptsetup_mutex);

		if (r == 0)
			break;
		printf("No key available with this passphrase.\n");
	}

free_out:
	crypt_free(cd);
notify_out:
	write(c->efd, &ok, sizeof(ok));
	return NULL;
}

static void start_cryptsetup(struct ueventconf *conf)
{
	dbg("starting cryptsetup %s -> %s", conf->crypt_devnode, conf->crypt_name);
	load_kmod("dm-crypt", NULL, 0);
	pthread_create(&conf->cryptsetup_tid, NULL, cryptsetup_thread, conf);
	conf->running_threads |= CRYPTSETUP_THREAD;
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

/* pathbuf needs hold PATH_MAX chars */
static void recurse_dir(char *pathbuf, struct recurse_opts *opts, int depth)
{
	DIR *d = opendir(pathbuf);
	struct dirent *entry;

	if (d == NULL)
		return;

	while ((entry = readdir(d)) != NULL) {
		size_t pathlen = strlen(pathbuf);
		size_t namelen = strlen(entry->d_name);
		int is_dir;

		/* d_type is not supported by all filesystems so we need
		   lstat */
		if (pathlen + 2 + namelen > PATH_MAX) {
			dbg("path length overflow");
			continue;
		}

		pathbuf[pathlen] = '/';
		strcpy(&pathbuf[pathlen+1], entry->d_name);

		if (entry->d_type == DT_UNKNOWN) {
			/* some filesystems like iso9660 does not support
			   the d_type so we use lstat */
			struct stat st;
			if (lstat(pathbuf, &st) < 0) {
				dbg("%s: %s", pathbuf, strerror(errno));
				goto next;
			}
			is_dir = S_ISDIR(st.st_mode);
		} else
			is_dir = entry->d_type & DT_DIR;

		if (is_dir) {
			if (entry->d_name[0] == '.')
				goto next;
		} else if (opts->searchname
			   && strcmp(entry->d_name, opts->searchname) != 0) {
			goto next;
		}

		if (is_dir) {
			if (depth > 0)
				recurse_dir(pathbuf, opts, depth - 1);
		} else
			opts->callback(pathbuf, opts->userdata);
next:
		pathbuf[pathlen] = '\0';
	}
	closedir(d);
}

struct bootrepos {
	char *outfile;
	int count;
};

static void bootrepo_cb(const char *path, const void *data)
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

	recurse_dir(mountdir, &opts, 2);
	if (repos.count > 0)
		rc |= FOUND_BOOTREPO;

	if (find_apkovl(mountdir, apkovls))
		rc |= FOUND_APKOVL;

	if (rc == 0)
		umount(mountdir);

	return rc;
}

static int is_same_device(const struct uevent *ev, const char *nodepath)
{
	struct stat st;
	unsigned int maj, min;
	if (stat(nodepath, &st) < 0)
		return 0;

	if (ev->major == NULL || ev->minor == NULL)
		return 0;

	maj = atoi(ev->major);
	min = atoi(ev->minor);
	return S_ISBLK(st.st_mode) && makedev(maj, min) == st.st_rdev;
}


static int searchdev(struct uevent *ev, const char *searchdev, char *bootrepos,
		     const char *apkovls)
{
	static blkid_cache cache = NULL;
	char *type = NULL, *label = NULL, *uuid = NULL;
	int rc = 0;

	if (searchdev == NULL && bootrepos == NULL && apkovls == NULL)
		return 0;

	if (searchdev && (strcmp(ev->devname, searchdev) == 0
			  || strcmp(ev->devnode, searchdev) == 0
	                  || is_same_device(ev, searchdev))) {
		return FOUND_DEVICE;
	}

	if (cache == NULL)
		blkid_get_cache(&cache, NULL);

	type = blkid_get_tag_value(cache, "TYPE", ev->devnode);

	if (searchdev != NULL) {
		if (strncmp("LABEL=", searchdev, 6) == 0) {
			label = blkid_get_tag_value(cache, "LABEL", ev->devnode);
			if (label && strcmp(label, searchdev+6) == 0)
				rc = FOUND_DEVICE;
		} else if (strncmp("UUID=", searchdev, 5) == 0) {
			uuid = blkid_get_tag_value(cache, "UUID", ev->devnode);
			if (uuid && strcmp(uuid, searchdev+5) == 0)
				rc = FOUND_DEVICE;
		}
	}

	if (type || label || uuid) {
		dbg("%s:\n"
			"\ttype='%s'\n"
			"\tlabel='%s'\n"
			"\tuuid='%s'\n", ev->devnode,
			type ? type : NULL,
			label ? label : NULL,
			uuid ? uuid : NULL);
	}

	if (!rc && type) {
		if (strcmp("linux_raid_member", type) == 0) {
			start_mdadm(ev->devnode);
		} else if (strcmp("LVM2_member", type) == 0) {
			start_lvm2(ev->devnode);
		} else if (bootrepos) {
			rc = find_bootrepos(ev->devnode, type, bootrepos, apkovls);
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

static int dispatch_uevent(struct uevent *ev, struct ueventconf *conf)
{
	static int timeout_increment = USB_STORAGE_TIMEOUT;

	if (conf->subsystem_filter && ev->subsystem
	    && strcmp(ev->subsystem, conf->subsystem_filter) != 0) {
		dbg("subsystem '%s' filtered out (by '%s').",
		    ev->subsystem, conf->subsystem_filter);
		return 0;
	}

	if (ev->action == NULL)
		return 0;

	if (ev->modalias != NULL && strcmp(ev->action, "add") == 0) {
		char buf[128];
		memset(buf, 0, sizeof(buf));
		load_kmod(ev->modalias, buf, sizeof(buf)-1);
		conf->modalias_count++;

		/* increase timeout so usb drives gets time to settle */
		if (strcmp(buf, "usb_storage") == 0) {
			conf->timeout += timeout_increment;
			timeout_increment = 0;
		}

	} else if (ev->devname != NULL) {
		if (conf->program_argv[0] != NULL) {
			spawn_command(&spawnmgr, conf->program_argv, ev->envp);
			conf->fork_count++;
		}

		if (ev->subsystem && strcmp(ev->subsystem, "block") == 0
		    && strcmp(ev->action, "add") == 0) {
			int rc;

			snprintf(ev->devnode, sizeof(ev->devnode), "/dev/%s",
				 ev->devname);
			pthread_mutex_lock(&conf->cryptsetup_mutex);
			rc = searchdev(ev, conf->search_device,
				       conf->bootrepos, conf->apkovls);
			pthread_mutex_unlock(&conf->cryptsetup_mutex);
			if (rc)
				return rc;

			if (searchdev(ev, conf->crypt_device, NULL, NULL)) {
				strncpy(conf->crypt_devnode,
					conf->crypt_device[0] == '/' ? conf->crypt_device : ev->devnode,
					sizeof(conf->crypt_devnode));
				start_cryptsetup(conf);
			}
		}
	}
	return 0;
}

static int process_uevent(char *buf, const size_t len, struct ueventconf *conf)
{
	struct uevent ev;

	int i, nenvp, slen = 0;
	char *key, *value;

	memset(&ev, 0, sizeof(ev));
	ev.buf = buf;
	ev.bufsize = len;

	nenvp = sizeof(default_envp) / sizeof(default_envp[0]) - 1;
	memcpy(&ev.envp, default_envp, nenvp * sizeof(default_envp[0]));

	for (i = 0; i < len; i += slen + 1) {
		key = buf + i;
		value = strchr(key, '=');
		slen = strlen(buf+i);

		if (i == 0 && slen != 0) {
			/* first line, the message */
			ev.message = key;
			continue;
		}

		if (!slen || !value)
			continue;

		value++;
		if (envcmp(key, "MODALIAS")) {
			ev.modalias = value;
		} else if (envcmp(key, "ACTION")) {
			ev.action = value;
		} else if (envcmp(key, "SUBSYSTEM")) {
			ev.subsystem = value;
		} else if (envcmp(key, "DEVNAME")) {
			ev.devname = value;
		} else if (envcmp(key, "MAJOR")) {
			ev.major = value;
		} else if (envcmp(key, "MINOR")) {
			ev.minor = value;
		}

		if (!envcmp(key, "PATH"))
			ev.envp[nenvp++]= key;
	}
	ev.envp[nenvp++] = 0;

	return dispatch_uevent(&ev, conf);
}

static void trigger_uevent_cb(const char *path, const void *data)
{
	int fd = open(path, O_WRONLY);
	write(fd, "add", 3);
	close(fd);
}

static void *trigger_thread(void *data)
{
	int fd = *(int *)data;
	uint64_t ok = TRIGGER_THREAD;
	struct recurse_opts opts = {
		.searchname = "uevent",
		.callback = trigger_uevent_cb,
		.userdata = NULL,
	};
	char path[PATH_MAX] = "/sys/bus";

	recurse_dir(path, &opts, 8);
	strcpy(path, "/sys/devices");
	recurse_dir(path, &opts, 8);
	write(fd, &ok, sizeof(ok));
	return NULL;
}

static void usage(int rc)
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
	" -t TIMEOUT      timeout after TIMEOUT milliseconds without uevents\n"
	"\n", argv0);

	exit(rc);
}

int main(int argc, char *argv[])
{
	struct pollfd fds[3];
	int numfds = 3;
	int r;
	struct ueventconf conf;
	int event_count = 0;
	size_t total_bytes = 0;
	int found = 0;
	int not_found_is_ok = 0;
	char *program_argv[2] = {0,0};
	pthread_t tid;
	sigset_t sigchldmask;

	for (r = 0; environ[r]; r++) {
		if (envcmp(environ[r], "PATH"))
			default_envp[0] = environ[r];
	}

	memset(&conf, 0, sizeof(conf));
	conf.program_argv = program_argv;
	conf.timeout = DEFAULT_EVENT_TIMEOUT;
	use_lvm = access(LVM_PATH, X_OK) == 0;
	use_mdadm = access(MDADM_PATH, X_OK) == 0;

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
	case 'n':
		not_found_is_ok = 1;
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
	case 't':
		conf.timeout = atoi(EARGF(usage(1)));
		break;
	default:
		usage(1);
	} ARGEND;

	if (argc > 0)
		conf.search_device = argv[0];

	r = pthread_mutex_init(&conf.cryptsetup_mutex, NULL);
	if (r < 0)
		err(1, "pthread_mutex_init");

	initsignals();
	sigemptyset(&sigchldmask);
	sigaddset(&sigchldmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigchldmask, NULL);

	fds[0].fd = init_netlink_socket();
	fds[0].events = POLLIN;

	fds[1].fd = signalfd(-1, &sigchldmask, SFD_NONBLOCK|SFD_CLOEXEC);
	fds[1].events = POLLIN;

	fds[2].fd = eventfd(0, EFD_CLOEXEC);
	fds[2].events = POLLIN;
	conf.efd = fds[2].fd;
	pthread_create(&tid, NULL, trigger_thread, &fds[2].fd);
	conf.running_threads |= TRIGGER_THREAD;

	while (1) {
		r = poll(fds, numfds, (spawn_active(&spawnmgr) || conf.running_threads) ? -1 : conf.timeout);
		if (r == -1) {
			if (errno == EINTR || errno == ERESTART)
				continue;
			err(1, "poll");
		}
		if (r == 0) {
			dbg("exit due to timeout (%i)", conf.timeout);
			break;
		}

		if (fds[0].revents & POLLIN) {
			size_t len;
			struct iovec iov;
			char cbuf[CMSG_SPACE(sizeof(struct ucred))];
			char buf[16384];
			struct cmsghdr *chdr;
			struct ucred *cred;
			struct msghdr hdr;
			struct sockaddr_nl cnls;

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
			    || ((found & FOUND_BOOTREPO) &&
				(found & FOUND_APKOVL))) {
				if (conf.timeout)
					dbg("FOUND! setting timeout to 0");
				conf.timeout = 0;
			}
		}

		if (fds[0].revents & POLLHUP) {
			dbg("parent hung up\n");
			break;
		}

		if (fds[1].revents & POLLIN) {
			struct signalfd_siginfo fdsi;
			pid_t pid;
			int status;

			while (read(fds[1].fd, &fdsi, sizeof fdsi) > 0)
				;
			while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
				spawn_reap(&spawnmgr, pid);
		}

		if (fds[2].revents & POLLIN) {
			uint64_t tmask = 0;
			if (read(fds[2].fd, &tmask, sizeof(tmask)) < 0)
				warn("eventfd");
			if (tmask & TRIGGER_THREAD) {
				dbg("terminating trigger thread");
				pthread_join(tid, NULL);
			}
			if (tmask & CRYPTSETUP_THREAD) {
				dbg("terminating cryptsetup thread");
				pthread_join(conf.cryptsetup_tid, NULL);
			}
			conf.running_threads &= ~tmask;
		}
	}
	close(fds[2].fd);
	pthread_mutex_destroy(&conf.cryptsetup_mutex);

	dbg("modaliases: %i, forks: %i, events: %i, total bufsize: %zu",
		conf.modalias_count,
		conf.fork_count,
		event_count, total_bytes);

	return found || not_found_is_ok ? 0 : 1;
}

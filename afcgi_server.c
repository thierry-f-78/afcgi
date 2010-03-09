/*
 * Copyright (c) 2009-2010 Thierry FOURNIER
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License.
 *
 */

#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "afcgi.h"

int afcgi_daemonize(char *pidfile) {
	int pid;
	int descriptor;
	FILE *pf;

	pid = fork();
	if (pid < 0) {
		afcgi_logmsg(LOG_ERR, "fork: %s", strerror(errno));
		return -1;
	}
	if (pid > 0){
		exit(0);
	}

	if (setsid() == -1) {
		afcgi_logmsg(LOG_ERR, "setsid: %s", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		afcgi_logmsg(LOG_ERR, "fork: %s", strerror(errno));
		return -1;
	}
	if(pid > 0){
		exit(0);
	}

	/* close standard file descriptors */
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);

	/* open standard descriptors on /dev/null */
	descriptor = open("/dev/null", O_RDWR);
	if (descriptor < 0) {
		afcgi_logmsg(LOG_ERR, "open: %s", strerror(errno));
		return -1;
	}
	if (dup(descriptor) == -1) {
		afcgi_logmsg(LOG_ERR, "dup: %s", strerror(errno));
		return -1;
	}
	if (dup(descriptor) == -1) {
		afcgi_logmsg(LOG_ERR, "dup: %s", strerror(errno));
		return -1;
	}

	/* end */
	if (pidfile == NULL)
		return 0;

	/* open lock/pid file */
	pf = fopen(pidfile, "w");
	if (pf == NULL) {
		afcgi_logmsg(LOG_ERR, "open(%s): %s", pidfile, strerror(errno));
		return -1;
	}
	
	/* write pid in lock file */
	fprintf(pf, "%d\n", (int)getpid());

	/* close pidfile */
	fclose(pf);

	/* return ok */
	return 0;
}

int afcgi_separe(char *user, char *chroot_dir, mode_t mask) {
	struct passwd *pwd = NULL;
	uid_t uid = 0;
	gid_t gid = 0;

	/* privilege separation
	 *
	 * Retrieve this data before chroot because, after chroot
	 * file are not accessible
	 */
	if (user != NULL) { 

		/* get uid and gid by username */
		pwd = getpwnam(user);
		if (pwd == NULL) {
			afcgi_logmsg(LOG_ERR, "getpwnam: %s", strerror(errno));
			return -1;
		}
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;

		/* set default group of user */
		if (setgid(gid) == -1) {
			afcgi_logmsg(LOG_ERR, "setgid: %s", strerror(errno));
			return -1;
		}

		/* use all groups assigned to user */
		if (initgroups(user, gid) == -1){
			afcgi_logmsg(LOG_ERR, "initgroups: %s", strerror(errno));
			return -1;
		}

		/* close passwd and groups */
		endpwent();
		endgrent();
	}

	/* chrooting */
	if (chroot_dir != NULL) {
			  
		/* chrooting */
		if (chroot(chroot_dir)) {
			afcgi_logmsg(LOG_ERR, "chroot(%s): %s", chroot_dir, strerror(errno));
			return -1;
		}

		/* change current directory */
		if (chdir("/")) {
			afcgi_logmsg(LOG_ERR, "chdir(/): %s", strerror(errno));
			return -1;
		}
	}

	/* change user */
	if (user != NULL) {
		if (setuid(uid) == -1) {
			afcgi_logmsg(LOG_ERR, "setuid: %s", strerror(errno));
			return -1;
		}
	}

	/* set file rights */
	umask(mask);

	/* return ok */
	return 0;
}

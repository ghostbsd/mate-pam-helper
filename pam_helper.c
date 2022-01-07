/*-
 * Copyright (c) 2008 Joe Marcus Clarke <marcus@FreeBSD.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $MCom: pam_helper/pam_helper.c,v 1.3 2016/09/18 18:10:46 jclarke Exp $
 *
 */
#include <sys/types.h>
#include <sys/uio.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <unistd.h>

#define PW_LEN BUFSIZ

static void *pamc_ptr = NULL;

static void
usage (void)
{
	fprintf(stderr, "usage: pam_helper service username\n");
	exit(1);
}

struct pam_closure {
	const char *user;
	const char *passwd;
};

static int pam_conversation (int nmsgs, const struct pam_message **msg, struct pam_response **resp, void *closure);

#define MESSAGE_PROMPT_ECHO_OFF 1
#define PROMPT "Password"

int
main (int argc, char **argv)
{
	pam_handle_t *pamh = NULL;
	int status = -1;
	ssize_t num_read, num_write;
	struct pam_conv pc;
	struct pam_closure c;
	char *passwd = NULL;
	char *user = NULL;
	char *service = NULL;
	int prompt_type = MESSAGE_PROMPT_ECHO_OFF;
	ssize_t msg_len;

	if (argc != 3)
		usage();

	service = strdup(argv[1]);
	user = strdup(argv[2]);

	passwd = (char *) calloc(PW_LEN + 1, sizeof (char));
	if (!passwd) {
		free(service);
		free(user);
		errx(1, "Failed to allocate password buffer.");
	}

	num_write = write(STDOUT_FILENO, &prompt_type, sizeof (prompt_type));
	if (num_write == sizeof (prompt_type)) {
		msg_len = strlen (PROMPT);
		num_write = write(STDOUT_FILENO, &msg_len, sizeof (msg_len));
		if (num_write == sizeof (msg_len)) {
			num_write = write(STDOUT_FILENO, PROMPT, msg_len);
			if (num_write != msg_len) {
				num_write = -1;
			}
		} else {
			num_write = -1;
		}
	} else {
		num_write = -1;
	}
	if (num_write < 0) {
		free(service);
		free(user);
		free(passwd);
		errx(1, "Failed to write prompt.");
	}

again:
	num_read = read(STDIN_FILENO, &msg_len, sizeof (msg_len));
	if (num_read == -1 && errno == EAGAIN)
		goto again;
	if (num_read == sizeof (msg_len)) {
		if (msg_len < PW_LEN) {
			num_read = read(STDIN_FILENO, passwd, msg_len);
			if (num_read == msg_len)
				passwd[msg_len] = '\0';
			else
				num_read = -1;
		} else {
			num_read = -1;
		}
	} else {
		num_read = -1;
	}
	if (num_read < 0) {
		free(service);
		free(user);
		free(passwd);
		errx(1, "Failed to read passwd.");
	}

	c.user = user;
	c.passwd = passwd;

	pc.conv = &pam_conversation;
	pc.appdata_ptr = (void *) &c;

	pamc_ptr = (void *) &c;

	status = pam_start(service, c.user, &pc, &pamh);
	if (status != PAM_SUCCESS) {
		free(service);
		free(user);
		free(passwd);
		errx(2, "Error starting PAM conversation.");
	}

	status = pam_authenticate(pamh, 0);
	if (status == PAM_SUCCESS) {
		int acct_status;

		acct_status = pam_acct_mgmt(pamh, 0);
		acct_status = pam_setcred(pamh, PAM_REINITIALIZE_CRED);

	} else {
		fprintf(stderr, "Error authenticating user.\n");
	}

	free(service);
	free(user);
	free(passwd);

	pam_end(pamh, status);

	return(status);
}

static int
pam_conversation (int nmsgs, const struct pam_message **msg,
		  struct pam_response **resp, void *closure)
{
	int replies = 0;
	struct pam_response *reply = NULL;
	struct pam_closure *c = (struct pam_closure *) closure;

	c = (struct pam_closure *) pamc_ptr;

	reply = (struct pam_response *) calloc (nmsgs, sizeof (*reply));
	if (!reply)
		return(PAM_CONV_ERR);

	for (replies = 0; replies < nmsgs; replies++) {
		switch (msg[replies]->msg_style) {
			case PAM_PROMPT_ECHO_ON:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = strdup(c->user);
				break;
			case PAM_PROMPT_ECHO_OFF:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = strdup (c->passwd);
				break;
			case PAM_TEXT_INFO:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = 0;
				break;
			case PAM_ERROR_MSG:
				reply[replies].resp_retcode = PAM_SUCCESS;
				reply[replies].resp = 0;
				break;
			default:
				free(reply);
				return(PAM_CONV_ERR);
		}
	}

	*resp = reply;
	return(PAM_SUCCESS);
}

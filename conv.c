/* pam_chk.c -- Checker for pam modules.
 * Author: Luis Colorado <luiscoloradourcola@gmail.com>
 * Date: Mon Dec 12 19:59:55 EET 2016
 * Disclaimer: (C) 2016 Luis Colorado.  All rights reserved.
 *
 * BSD 3-Clause License
 * 
 * Copyright (c) 2016, Luis Colorado All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the
 * following conditions are met:
 * 
 * Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.
 * 
 * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials
 * provided with the distribution.
 * 
 * Neither the name of the copyright holder nor the names of
 * its contributors may be used to endorse or promote products
 * derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "conv.h"

#define F(x) __FILE__":%d:%s: " x, __LINE__, __func__

static char *message_type(int n, char *buf, size_t bsz);

int conv(int n,
	const struct pam_message **rcv,
	struct pam_response **snt,
	void *p)
{
	int i;
	char buffer[32];
	char line[PAM_MAX_RESP_SIZE];
	char *str;

	*snt = calloc(n, sizeof *snt);

	for (i = 0; i < n; i++) {
		printf(F("message#%d: type=%s; message=[%s]\n"),
			i, message_type(rcv[i]->msg_style,
			buffer, sizeof buffer), rcv[i]->msg);
		switch(rcv[i]->msg_style){
		case PAM_PROMPT_ECHO_OFF:

		case PAM_PROMPT_ECHO_ON:
			snt[i] = malloc(sizeof *snt[i]);
			snprintf(line, sizeof line, "user_resp[%d]", i);
			snt[i]->resp = strdup(line);
			snt[i]->resp_retcode = 0;
			break;
		} /* switch */
	} /* for */

	return PAM_SUCCESS;
} /* conv */

static char *message_type(int n, char *buf, size_t bsz)
{
	switch(n) {

#define C(m) case PAM_ ## m: return "PAM_" #m
	C(PROMPT_ECHO_OFF);
	C(PROMPT_ECHO_ON);
	C(ERROR_MSG);
	C(TEXT_INFO);
#undef C

	default:
		snprintf(buf, bsz,"UNKNOWN(%d)", n);
		return buf;

	} /* switch */

	/* NOTREACHED */

} /* message_type */

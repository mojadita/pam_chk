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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <locale.h>

#include <sys/types.h>
#include <security/pam_appl.h>

#include "conv.h"

#define F(x) __FILE__":%d:%s: " x, __LINE__, __func__
#define D(cmd) do{ \
		res = cmd; \
		printf(F(#cmd " => %d (%s)\n"), res, pam_strerror(state.ph, res)); \
	} while(0)

const char *progname;
char *user = NULL,
	*service = NULL;

int main(int argc, char **argv)
{
	int opt, res;
	struct conv_state state;
	struct pam_conv callback_info;

	progname = argv[0];
	setlocale(LC_ALL, "");

	while ((opt = getopt(argc, argv, "")) != EOF) {
		switch(opt) {
		}
	} /* while */

	argc -= optind;
	argv += optind;

	if (argc) {
		service = *argv++;
		argc--;
	}

	if (argc) {
		user = *argv++;
		argc--;
	}

	if (!service || argc) {
		fprintf(stderr,
			F("usage: %s [ options ... ] service [ user ]\n"),
			progname);
		exit(EXIT_FAILURE);
	}


	printf(F("uid=%d; euid=%d\n"), getuid(), geteuid());
	printf(F("service = %s; user = %s;\n"),
		service, user ? user : "<<NO_USER_INDICATED>>");
	callback_info.conv = conv;
	callback_info.appdata_ptr = NULL;

	state.user = NULL;
	state.pass = NULL;

	D(pam_start(service, user, &callback_info, &state.ph));
	D(pam_authenticate(state.ph, 0));
	D(pam_end(state.ph, res));

	exit(EXIT_SUCCESS);

} /* main */

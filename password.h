/*
 * UNFS3 mount password support routines
 * (C) 2004, Peter Astrand <astrand@cendio.se>
 * see file LICENSE for license details
 */

int gen_nonce(char *nonce);

void mnt_cmd_argument(char **dpath, const char *cmd, char *arg, size_t maxlen);

void otp_digest(char nonce[32], 
		char *password, 
		char hexdigest[32]);

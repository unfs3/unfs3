/*
 * UNFS3 mount password support routines
 * (C) 2004, Peter Astrand <peter@cendio.se>
 * see file LICENSE for license details
 */

void gen_nonce(char *nonce);

void mnt_cmd_argument(char **dpath, const char *cmd, char *arg, size_t maxlen);

void otp_digest(char nonce[32], 
		unsigned char *password, 
		unsigned char hexdigest[32]);

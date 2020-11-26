%{
/*
 * UNFS3 exports lexer
 * (C) 2003, Pascal Schmidt
 * see file LICENSE for license details
 */
#include "config.h"

#include <rpc/rpc.h>
#include <string.h>

#include "nfs.h"
#include "y.tab.h"

#define YY_NO_UNPUT

extern YYSTYPE yylval;
extern int e_error;

/*
 * copy matching text to yylval.text
 */
static void copy_text(const char *from, int leng)
{
	int len;

	/* check length to prevent buffer overflow */	
	if (leng + 1 > NFS_MAXPATHLEN) {
		len = NFS_MAXPATHLEN - 1;
		e_error = 1;
	} else
		len = leng;

	memcpy(yylval.text, from, len);
	yylval.text[len] = 0;
}
%}

WHITE [ \t]
NOWHITE [^ \n\t]
PATH "/"{NOWHITE}*
ID [a-z][\.\-_a-z0-9]*
OPTVALUE [^ \n\t,)]*

/* From RFC grammar */
dec_octet      ([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])
ipv4address    ({dec_octet}"."){3}{dec_octet}
h16            ([[:xdigit:]]{1,4})
ls32           ({h16}:{h16}|{ipv4address})
ipv6address    (({h16}:){6}{ls32}|::({h16}:){5}{ls32}|({h16})?::({h16}:){4}{ls32}|(({h16}:){0,1}{h16})?::({h16}:){3}{ls32}|(({h16}:){0,2}{h16})?::({h16}:){2}{ls32}|(({h16}:){0,3}{h16})?::{h16}:{ls32}|(({h16}:){0,4}{h16})?::{ls32}|(({h16}:){0,5}{h16})?::{h16}|(({h16}:){0,6}{h16})?::)

ipv4prefix ([0-9]|[1-2][0-9]|3[0-2])
ipv6prefix ([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])

IPV4 {ipv4address}
IPV6 {ipv6address}
IPV4NET {ipv4address}"/"{ipv4prefix}
IPV6NET {ipv6address}"/"{ipv6prefix}
OLDNET {ipv4address}"/"{ipv4address}

%option nounput
%option noinput
%option noyywrap

%%

^{WHITE}*\n		{ /* eat empty line */ }
^{WHITE}*		{ /* eat whitespace at beginning of line */ }
"\\"\n			{ /* eat escaped newline */ }
^{WHITE}*"#".*\n	{ /* eat one-line comment */ }
{WHITE}*"#".*		{ /* eat trailing comment */ }

{IPV4}			{ copy_text(yytext, yyleng); return IPV4; }
{IPV6}			{ copy_text(yytext, yyleng); return IPV6; }
{IPV4NET}		{ copy_text(yytext, yyleng); return IPV4NET; }
{IPV6NET}		{ copy_text(yytext, yyleng); return IPV6NET; }
{OLDNET}		{ copy_text(yytext, yyleng); return OLDNET; }
"\"".*"\""		{ copy_text(yytext+1, yyleng-2); return PATH; }
"="{OPTVALUE}	        { copy_text(yytext+1, yyleng-1); return OPTVALUE; }
{PATH}			{ copy_text(yytext, yyleng); return PATH; }
{WHITE}+		{ copy_text(yytext, yyleng); return WHITE; }
{ID}			{ copy_text(yytext, yyleng); return ID; }

.			{ return *yytext; }
\n			{ return '\n'; }
   

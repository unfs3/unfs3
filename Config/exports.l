%{
/*
 * UNFS3 exports lexer
 * (C) 2003, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */
#include "../config.h"

#include <rpc/rpc.h>
#include <string.h>

#include "../nfs.h"
#include "y.tab.h"

YYSTYPE yylval;
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
OPTVAL [^ \n\t,)]*

IPCOMP [0-9]{1,3}
IP {IPCOMP}"."{IPCOMP}"."{IPCOMP}"."{IPCOMP}
NETCOMP [0-9]{1,2}
NET {IP}"/"{NETCOMP}
OLDNET {IP}"/"{IP}

%%

^{WHITE}*\n		{ /* eat empty line */ }
^{WHITE}*		{ /* eat whitespace at beginning of line */ }
"\\"\n			{ /* eat escaped newline */ }
^{WHITE}*"#".*\n	{ /* eat one-line comment */ }
{WHITE}*"#".*		{ /* eat trailing comment */ }

{IP}			{ copy_text(yytext, yyleng); return IP; }
{NET}			{ copy_text(yytext, yyleng); return NET; }
{OLDNET}		{ copy_text(yytext, yyleng); return OLDNET; }
"\"".*"\""		{ copy_text(yytext+1, yyleng-2); return PATH; }
"="{OPTVAL}	        { copy_text(yytext+1, yyleng-1); return OPTVAL; }
{PATH}			{ copy_text(yytext, yyleng); return PATH; }
{WHITE}+		{ copy_text(yytext, yyleng); return WHITE; }
{ID}			{ copy_text(yytext, yyleng); return ID; }

.			{ return *yytext; }
\n			{ return '\n'; }
   
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */
#include "otr.h"

int debug = 0;
hexchat_plugin *ph;
static GRegex *regex_nickignore = NULL;

static char set_policy[512] = IO_DEFAULT_POLICY;
static char set_policy_known[512] = IO_DEFAULT_POLICY_KNOWN;
static char set_ignore[512] = IO_DEFAULT_IGNORE;
static int set_finishonunload = TRUE;

static int get_current_context_type (void)
{
	return hexchat_list_int (ph, NULL, "type");
}

static int extract_nick (char *nick, char *line, size_t nick_size)
{
	char *excl;

	if (*line++ != ':')
		return FALSE;

	g_strlcpy (nick, line, nick_size);

	if ((excl = strchr (nick, '!')))
		*excl = '\0';

	return TRUE;
}

void irc_send_message (IRC_CTX *ircctx, const char *recipient, char *msg)
{
	hexchat_commandf (ph, "PRIVMSG %s :%s", recipient, msg);
}

static void cmd_start (const char *nick)
{
	if (get_current_context_type () != 3)
	{
		hexchat_print (ph, "OTR: You can only use OTR in a dialog\n");
		return;
	}

	hexchat_commandf (ph, "quote PRIVMSG %s :?OTRv23?", nick);
}

static int cmd_otr (char *word[], char *word_eol[], void *userdata)
{
	const char *own_nick = hexchat_get_info (ph, "nick");
	char *target = (char *)hexchat_get_info (ph, "channel");
	const char *network = hexchat_get_info (ph, "network");
	IRC_CTX ircctxs = {
				.nick = (char *)own_nick,
				.address = (char *)network
			},
			*ircctx = &ircctxs;

	char *cmd = word[2];

	if (!cmd)
	{
		hexchat_command(ph, "help otr");
		return HEXCHAT_EAT_ALL;
	}

	if (strcmp (cmd, "debug") == 0)
	{
		debug = !debug;
		otr_noticest (debug ? TXT_CMD_DEBUG_ON : TXT_CMD_DEBUG_OFF);
	}
	else if (strcmp (cmd, "start") == 0 || strcmp (cmd, "init") == 0)
	{
		cmd_start (target);
	}
	else if (strcmp (cmd, "version") == 0)
	{
		otr_noticest (TXT_CMD_VERSION, PVERSION);
	}
	else if (strcmp (cmd, "finish") == 0)
	{
		if (word[3] && *word[3])
			otr_finish (NULL, NULL, word[3], TRUE);
		else
			otr_finish (ircctx, target, NULL, TRUE);
	}
	else if (strcmp (cmd, "trust") == 0)
	{
		if (word[3] && *word[3])
			otr_trust (NULL, NULL, word[3]);
		else
			otr_trust (ircctx, target, NULL);
	}
	else if (strcmp (cmd, "authabort") == 0)
	{
		if (word[3] && *word[3])
			otr_authabort (NULL, NULL, word[3]);
		else
			otr_authabort (ircctx, target, NULL);
	}
	else if (strcmp (cmd, "genkey") == 0)
	{
		if (word[3] && *word[3])
		{
			if (strcmp (word[3], "abort") == 0)
				keygen_abort (FALSE);
			else if (strchr (word[3], '@'))
				keygen_run (word[3]);
			else
				otr_noticest (TXT_KG_NEEDACC);
		}
		else
		{
			otr_noticest (TXT_KG_NEEDACC);
		}
	}
	else if (strcmp (cmd, "auth") == 0)
	{
		if (!word[3] || !*word[3])
			otr_notice (ircctx, target, TXT_CMD_AUTH);
		else if (word[4] && *word[4] && strchr (word[3], '@'))
			otr_auth (NULL, NULL, word[3], NULL, word_eol[4]);
		else
			otr_auth (ircctx, target, NULL, NULL, word_eol[3]);
	}
	else if (strcmp (cmd, "authq") == 0)
	{
		if (!word[3] || !*word[3] || !word[4] || !*word[4])
			otr_notice (ircctx, target, TXT_CMD_AUTH);
		else if (word[5] && *word[5] && strchr (word[3], '@'))
			otr_auth (NULL, NULL, word[3], word[5], word[4]);
		else
			otr_auth (ircctx, target, NULL, word[4], word_eol[5]);
	}
	else if (strcmp (cmd, "set") == 0)
	{
		if (strcmp (word[3], "policy") == 0)
		{
			otr_setpolicies (word_eol[4], FALSE);
			g_strlcpy (set_policy, word_eol[4], sizeof(set_policy));
		}
		else if (strcmp (word[3], "policy_known") == 0)
		{
			otr_setpolicies (word_eol[4], TRUE);
			g_strlcpy (set_policy_known, word_eol[4], sizeof(set_policy_known));
		}
		else if (strcmp (word[3], "ignore") == 0)
		{
			if (regex_nickignore)
				g_regex_unref (regex_nickignore);
			regex_nickignore = g_regex_new (word_eol[4], 0, 0, NULL);
			g_strlcpy (set_ignore, word_eol[4], sizeof(set_ignore));
		}
		else if (strcmp (word[3], "finishonunload") == 0)
		{
			set_finishonunload = (g_ascii_strcasecmp (word[4], "true") == 0);
		}
		else
		{
			hexchat_printf (ph, "policy: %s\n"
								"policy_known: %s\nignore: %s\n"
								"finishonunload: %s\n",
							set_policy, set_policy_known, set_ignore,
							set_finishonunload ? "true" : "false");
		}
	}
	else
		hexchat_command(ph, "help otr");

	return HEXCHAT_EAT_ALL;
}

static int hook_outgoing (char *word[], char *word_eol[], void *userdata)
{
	const char *own_nick = hexchat_get_info (ph, "nick");
	const char *channel = hexchat_get_info (ph, "channel");
	const char *network = hexchat_get_info (ph, "network");
	char newmsg[512];
	char *otrmsg;
	IRC_CTX ircctx = {
		.nick = (char *)own_nick,
		.address = (char *)network
	};

	if (get_current_context_type () != 3) /* Not PM */
		return HEXCHAT_EAT_NONE;

	if (g_regex_match (regex_nickignore, channel, 0, NULL))
		return HEXCHAT_EAT_NONE;
	otrmsg = otr_send (&ircctx, word_eol[1], channel);

	if (otrmsg == word_eol[1])
		return HEXCHAT_EAT_NONE;

	hexchat_emit_print (ph, "Your Message", own_nick, word_eol[1], NULL, NULL);

	if (!otrmsg)
		return HEXCHAT_EAT_ALL;

	g_snprintf (newmsg, 511, "PRIVMSG %s :%s", channel, otrmsg);

	otrl_message_free (otrmsg);
	hexchat_command (ph, newmsg);

	return HEXCHAT_EAT_ALL;
}

static int hook_privmsg (char *word[], char *word_eol[], void *userdata)
{
	char nick[256];
	char *newmsg;
	const char *network = hexchat_get_info (ph, "network");
	const char *own_nick = hexchat_get_info (ph, "nick");
	const char *chantypes = hexchat_list_str (ph, NULL, "chantypes");
	IRC_CTX ircctx = {
		.nick = (char *)own_nick,
		.address = (char *)network
	};
	hexchat_context *query_ctx;

	if (strchr (chantypes, word[3][0]) != NULL) /* Ignore channels */
		return HEXCHAT_EAT_NONE;

	if (!extract_nick (nick, word[1], sizeof(nick)))
		return HEXCHAT_EAT_NONE;

	if (g_regex_match (regex_nickignore, nick, 0, NULL))
		return HEXCHAT_EAT_NONE;

	newmsg = otr_receive (&ircctx, word_eol[2], nick);

	if (!newmsg)
	{
		return HEXCHAT_EAT_ALL;
	}

	if (newmsg == word_eol[2])
	{
		return HEXCHAT_EAT_NONE;
	}

	query_ctx = hexchat_find_context (ph, network, nick);
	if (query_ctx == NULL)
	{
		hexchat_commandf (ph, "query %s", nick);
		query_ctx = hexchat_find_context (ph, network, nick);
	}

	GRegex *regex_quot = g_regex_new ("&quot;", 0, 0, NULL);
	GRegex *regex_amp = g_regex_new ("&amp;", 0, 0, NULL);
	GRegex *regex_lt = g_regex_new ("&lt;", 0, 0, NULL);
	GRegex *regex_gt = g_regex_new ("&gt;", 0, 0, NULL);
	char *quotfix = g_regex_replace_literal (regex_quot, newmsg, -1, 0, "\"", 0, NULL);
	char *ampfix = g_regex_replace_literal (regex_amp, quotfix, -1, 0, "&", 0, NULL);
	char *ltfix = g_regex_replace_literal (regex_lt, ampfix, -1, 0, "<", 0, NULL);
	char *gtfix = g_regex_replace_literal (regex_gt, ltfix, -1, 0, ">", 0, NULL);
	newmsg = gtfix;

	g_regex_unref (regex_quot);
	g_regex_unref (regex_amp);
	g_regex_unref (regex_lt);
	g_regex_unref (regex_gt);

	if (query_ctx)
		hexchat_set_context (ph, query_ctx);

	hexchat_emit_print (ph, "Private Message", nick, newmsg, NULL, NULL);

	hexchat_command (ph, "GUI COLOR 2");
	otrl_message_free (newmsg);

	return HEXCHAT_EAT_ALL;
}

void hexchat_plugin_get_info (char **name, char **desc, char **version, void **reserved)
{
	*name = PNAME;
	*desc = PDESC;
	*version = PVERSION;
}

int hexchat_plugin_init (hexchat_plugin *plugin_handle,
						 char **plugin_name,
						 char **plugin_desc,
						 char **plugin_version,
						 char *arg)
{
	ph = plugin_handle;

	*plugin_name = PNAME;
	*plugin_desc = PDESC;
	*plugin_version = PVERSION;

	if (otrlib_init ())
		return 0;

	hexchat_hook_server (ph, "PRIVMSG", HEXCHAT_PRI_NORM, hook_privmsg, 0);
	hexchat_hook_command (ph, "", HEXCHAT_PRI_NORM, hook_outgoing, 0, 0);
	hexchat_hook_command (ph, "otr", HEXCHAT_PRI_NORM, cmd_otr, OTR_HELP, 0);

	otr_setpolicies (IO_DEFAULT_POLICY, FALSE);
	otr_setpolicies (IO_DEFAULT_POLICY_KNOWN, TRUE);

	if (regex_nickignore)
		g_regex_unref (regex_nickignore);
	regex_nickignore = g_regex_new (IO_DEFAULT_IGNORE, 0, 0, NULL);

	hexchat_print (ph, "Hexchat OTR loaded successfully!\n");

	return 1;
}

int hexchat_plugin_deinit (void)
{
	g_regex_unref (regex_nickignore);

	if (set_finishonunload)
		otr_finishall ();

	otrlib_deinit ();

	return 1;
}

void otr_log(IRC_CTX *server, const char *nick, int level, const char *format, ...)
{
	/* TODO: Implement me! */
}

void printformat (IRC_CTX *ircctx, const char *nick, int lvl, int fnum, ...)
{
	va_list params;
	va_start (params, fnum);
	char msg[LOGMAX], *s = msg;
	hexchat_context *find_query_ctx;
	char *network = NULL;

	if (ircctx)
		network = ircctx->address;

	if (network && nick)
	{
		find_query_ctx = hexchat_find_context (ph, network, nick);
		if (find_query_ctx == NULL)
		{
			/* no query window yet, let's open one */
			hexchat_commandf (ph, "query %s", nick);
			find_query_ctx = hexchat_find_context (ph, network, nick);
		}
	}
	else
	{
		find_query_ctx = hexchat_find_context (ph,
											   NULL,
											   hexchat_get_info (ph,
																 "network")
												   ?: hexchat_get_info (ph, "network"));
	}

	hexchat_set_context (ph, find_query_ctx);

#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	if (g_vsnprintf (msg, sizeof(msg), formats[fnum].def, params) < 0)
#pragma GCC diagnostic pop
		g_snprintf (msg, sizeof(msg), "internal error parsing error string (BUG)");
	va_end (params);
	hexchat_printf (ph, "OTR: %s", s);
}

IRC_CTX *server_find_address (char *address)
{
	static IRC_CTX ircctx;

	ircctx.address = address;

	return &ircctx;
}

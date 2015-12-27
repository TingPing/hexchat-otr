/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
 *
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

#include <gcrypt.h>

OtrlUserState otr_state = NULL;
extern OtrlMessageAppOps otr_ops;
static int otrinited = FALSE;
GSList *plistunknown = NULL;
GSList *plistknown = NULL;
GRegex *regex_policies = NULL;

#define MSGQUEUE_LEN 4096

/*
 * init otr lib.
 */
int otrlib_init ()
{

	if (!otrinited)
	{
		OTRL_INIT;
		otrinited = TRUE;
	}

	otr_state = otrl_userstate_create ();

	/* load keys and fingerprints */

	instag_load ();
	key_load ();
	fps_load ();

	otr_initops ();

	regex_policies = g_regex_new ("([^,]+) (never|manual|handlews|opportunistic|always)"
								  "(,|$)",
								  0, 0, NULL);

	return otr_state == NULL;
}

/*
 * deinit otr lib.
 */
void otrlib_deinit ()
{
	if (otr_state)
	{
		otr_writefps ();
		otrl_userstate_free (otr_state);
		otr_state = NULL;
	}

	keygen_abort (TRUE);

	otr_setpolicies ("", FALSE);
	otr_setpolicies ("", TRUE);

	g_regex_unref (regex_policies);
}

/*
 * Free our app data.
 */
void context_free_app_info (void *data)
{
	struct co_info *coi = data;
	if (coi->msgqueue)
	{
		g_free (coi->msgqueue);
	}
	if (coi->ircctx)
		IRCCTX_FREE (coi->ircctx);
}

/*
 * Add app data to context.
 * See struct co_info for details.
 */
void context_add_app_info (void *data, ConnContext *co)
{
	IRC_CTX *ircctx = IRCCTX_DUP (data);
	struct co_info *coi = g_malloc (sizeof(struct co_info));

	memset (coi, 0, sizeof(struct co_info));
	co->app_data = coi;
	co->app_data_free = context_free_app_info;

	coi->ircctx = ircctx;
	g_snprintf (coi->better_msg_two, sizeof(coi->better_msg_two),
				formats[TXT_OTR_BETTER_TWO].def, co->accountname);
}

/*
 * Get a context from a pair.
 */
ConnContext *otr_getcontext (const char *accname, const char *nick,
							 int create, void *data)
{
	ConnContext *co = otrl_context_find (
		otr_state,
		nick,
		accname,
		PROTOCOLID,
		OTRL_INSTAG_BEST,
		create,
		FALSE,
		context_add_app_info,
		data);

	/* context came from a fingerprint */
	if (co && data && !co->app_data)
		context_add_app_info (data, co);

	return co;
}

/*
 * Hand the given message to OTR.
 * Returns NULL if OTR handled the message and 
 * the original message otherwise.
 */
char *otr_send (IRC_CTX *ircctx, const char *msg, const char *to)
{
	const char *nick = IRCCTX_NICK (ircctx);
	const char *address = IRCCTX_ADDR (ircctx);
	gcry_error_t err;
	char *newmessage = NULL;
	ConnContext *co;
	char accname[256];

	g_snprintf (accname, sizeof(accname), "%s@%s", nick, address);

	if (!(co = otr_getcontext (accname, to, TRUE, ircctx)))
	{
		otr_noticest (TXT_CTX_NOT_CREATE,
                                          accname, to);
		return NULL;
	}

	err = otrl_message_sending (
		otr_state,
		&otr_ops,
		ircctx,
		accname,
		PROTOCOLID,
		to,
		OTRL_INSTAG_BEST,
		msg,
		NULL,
		&newmessage,
		OTRL_FRAGMENT_SEND_ALL,
		&co,
		context_add_app_info,
		ircctx);

	if (err != 0)
	{
		otr_notice (ircctx, to, TXT_SEND_FAILED, msg);
		return NULL;
	}

	if (newmessage == NULL)
		return (char *)msg;

	return NULL;
}

struct ctxlist_ *otr_contexts ()
{
	ConnContext *context;
	Fingerprint *fprint;
	struct ctxlist_ *ctxlist = NULL, *ctxhead = NULL;
	struct fplist_ *fplist, *fphead;
	char fp[41];
	char *trust;
	int i;

	for (context = otr_state->context_root; context;
		 context = context->next)
	{
		if (!ctxlist)
			ctxhead = ctxlist = g_malloc0 (sizeof(struct ctxlist_));
		else
			ctxlist = ctxlist->next = g_malloc0 (sizeof(struct
														ctxlist_));
		switch (context->msgstate)
		{
		case OTRL_MSGSTATE_PLAINTEXT:
			ctxlist->state = STUNENCRYPTED;
			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			ctxlist->state = STENCRYPTED;
			break;
		case OTRL_MSGSTATE_FINISHED:
			ctxlist->state = STFINISHED;
			break;
		default:
			ctxlist->state = STUNKNOWN;
			break;
		}
		ctxlist->username = context->username;
		ctxlist->accountname = context->accountname;

		fplist = fphead = NULL;
		for (fprint = context->fingerprint_root.next; fprint;
			 fprint = fprint->next)
		{
			if (!fplist)
				fphead = fplist = g_malloc0 (sizeof(struct
													fplist_));
			else
				fplist = fplist->next = g_malloc0 (sizeof(struct
														  fplist_));
			trust = fprint->trust ?: "";
			for (i = 0; i < 20; ++i)
				sprintf (fp + i * 2, "%02x",
						 fprint->fingerprint[i]);
			fplist->fp = g_strdup (fp);
			if (*trust == '\0')
				fplist->authby = NOAUTH;
			else if (strcmp (trust, "smp") == 0)
				fplist->authby = AUTHSMP;
			else
				fplist->authby = AUTHMAN;
		}

		ctxlist->fplist = fphead;
	}
	return ctxhead;
}

/*
 * Get the OTR status of this conversation.
 */
int otr_getstatus(IRC_CTX *ircctx, const char *nick)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;

	g_snprintf (accname, sizeof(accname), "%s@%s", ircctx->nick, ircctx->address);

	if (!(co = otr_getcontext(accname, nick, FALSE, ircctx)))
	{
		return IO_ST_PLAINTEXT;
	}

	coi = co->app_data;

	switch (co->msgstate)
	{
	case OTRL_MSGSTATE_PLAINTEXT:
		return IO_ST_PLAINTEXT;
	case OTRL_MSGSTATE_ENCRYPTED:
	{
		char *trust = co->active_fingerprint->trust;
		int ex = co->smstate->nextExpected;
		int code = 0;

		switch (ex)
		{
		case OTRL_SMP_EXPECT1:
			if (coi->received_smp_init)
				code = IO_ST_SMP_INCOMING;
			break;
		case OTRL_SMP_EXPECT2:
			code = IO_ST_SMP_OUTGOING;
			break;
		case OTRL_SMP_EXPECT3:
		case OTRL_SMP_EXPECT4:
			code = IO_ST_SMP_FINALIZE;
			break;
		default:
			otr_logst(
				MSGLEVEL_CRAP,
				"Encountered unknown SMP state in libotr, please let maintainers know");
			return IO_ST_UNKNOWN;
		}

		if (trust && (*trust != '\0'))
			code |= strcmp(trust, "smp") == 0 ? IO_ST_TRUST_SMP :
				IO_ST_TRUST_MANUAL;
		else
			code |= IO_ST_UNTRUSTED;

		return code;
	}
	case OTRL_MSGSTATE_FINISHED:
		return IO_ST_FINISHED;
	default:
		otr_logst(
			MSGLEVEL_CRAP,
			"BUG Found! Please write us a mail and describe how you got here");
		return IO_ST_UNKNOWN;
	}
}

/*
 * Finish the conversation.
 */
void otr_finish (IRC_CTX *ircctx, char *nick, const char *peername, int inquery)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;
	char *pserver = NULL;

	if (peername)
	{
		pserver = strchr (peername, '@');
		if (!pserver)
			return;
		ircctx = server_find_address (pserver + 1);
		if (!ircctx)
			return;
		*pserver = '\0';
		nick = (char *)peername;
	}

	g_snprintf (accname, sizeof(accname), "%s@%s", IRCCTX_NICK (ircctx), IRCCTX_ADDR (ircctx));

	if (!(co = otr_getcontext (accname, nick, FALSE, NULL)))
	{
		if (inquery)
			otr_noticest (TXT_CTX_NOT_FOUND,
						  accname, nick);
		if (peername)
			*pserver = '@';
		return;
	}

	otrl_message_disconnect (otr_state, &otr_ops, ircctx, accname,
							 PROTOCOLID, nick, OTRL_INSTAG_BEST);

	if (inquery)
	{
		otr_info (ircctx, nick, TXT_CMD_FINISH, nick, IRCCTX_ADDR (ircctx));
	}
	else
	{
		otr_infost (TXT_CMD_FINISH, nick, IRCCTX_ADDR (ircctx));
	}

	coi = co->app_data;

	/* finish if /otr finish has been issued. Reset if
	 * we're called cause the query window has been closed. */
	if (coi)
		coi->finished = inquery;

	/* write the finished into the master as well */
	co = otrl_context_find(
		otr_state,
		nick,
		accname,
		PROTOCOLID,
		OTRL_INSTAG_MASTER,
		FALSE,
		NULL,
		NULL,
		NULL);
	coi = co->app_data;
	if (coi)
		coi->finished = inquery;

	if (peername)
		*pserver = '@';
}

void otr_finishall ()
{
	ConnContext *context;
	int finished = 0;

	for (context = otr_state->context_root; context;
		 context = context->next)
	{
		struct co_info *coi = context->app_data;

		if (context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
			continue;

		otrl_message_disconnect (otr_state, &otr_ops, coi->ircctx,
								 context->accountname,
								 PROTOCOLID,
								 context->username,
								 OTRL_INSTAG_BEST);

		otr_infost (TXT_CMD_FINISH, context->username,
					IRCCTX_ADDR (coi->ircctx));
		finished++;
	}

	if (!finished)
		otr_infost (TXT_CMD_FINISHALL_NONE);
}

/*
 * Trust our peer.
 */
void otr_trust (IRC_CTX *ircctx, char *nick, const char *peername)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;
	char *pserver = NULL;

	if (peername)
	{
		pserver = strchr (peername, '@');
		if (!pserver)
			return;
		ircctx = server_find_address (pserver + 1);
		if (!ircctx)
			return;
		*pserver = '\0';
		nick = (char *)peername;
	}

	g_snprintf (accname, sizeof(accname), "%s@%s", IRCCTX_NICK (ircctx), IRCCTX_ADDR (ircctx));

	if (!(co = otr_getcontext (accname, nick, FALSE, NULL)))
	{
		otr_noticest (TXT_CTX_NOT_FOUND,
					  accname, nick);
		if (peername)
			*pserver = '@';
		return;
	}

	otrl_context_set_trust (co->active_fingerprint, "manual");

	coi = co->app_data;
	coi->smp_failed = FALSE;

	otr_notice (ircctx, nick, TXT_FP_TRUST, nick);

	if (peername)
		*pserver = '@';
}

/*
 * Abort any ongoing SMP authentication.
 */
void otr_abort_auth (ConnContext *co, IRC_CTX *ircctx, const char *nick)
{
	struct co_info *coi;

	coi = co->app_data;

	coi->received_smp_init = FALSE;

	otr_notice (ircctx, nick,
				co->smstate->nextExpected != OTRL_SMP_EXPECT1 ? TXT_AUTH_ABORTED_ONGOING : TXT_AUTH_ABORTED);

	otrl_message_abort_smp (otr_state, &otr_ops, ircctx, co);
}

/*
 * implements /otr authabort
 */
void otr_authabort (IRC_CTX *ircctx, char *nick, const char *peername)
{
	ConnContext *co;
	char accname[128];
	char *pserver = NULL;

	if (peername)
	{
		pserver = strchr (peername, '@');
		if (!pserver)
			return;
		ircctx = server_find_address (pserver + 1);
		if (!ircctx)
			return;
		*pserver = '\0';
		nick = (char *)peername;
	}

	g_snprintf (accname, sizeof(accname), "%s@%s", IRCCTX_NICK (ircctx), IRCCTX_ADDR (ircctx));

	if (!(co = otr_getcontext (accname, nick, FALSE, NULL)))
	{
		otr_noticest (TXT_CTX_NOT_FOUND,
					  accname, nick);
		if (peername)
			*pserver = '@';
		return;
	}

	otr_abort_auth (co, ircctx, nick);

	if (peername)
		*pserver = '@';
}

/*
 * Initiate or respond to SMP authentication.
 */
void otr_auth (IRC_CTX *ircctx, char *nick, const char *peername, const char *question,
								const char *secret)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;
	char *pserver = NULL;

	if (peername)
	{
		pserver = strchr (peername, '@');
		if (!pserver)
			return;
		ircctx = server_find_address (pserver + 1);
		if (!ircctx)
			return;
		*pserver = '\0';
		nick = (char *)peername;
	}

	g_snprintf (accname, sizeof(accname), "%s@%s", IRCCTX_NICK (ircctx), IRCCTX_ADDR (ircctx));

	if (!(co = otr_getcontext (accname, nick, FALSE, NULL)))
	{
		otr_noticest (TXT_CTX_NOT_FOUND,
					  accname, nick);
		if (peername)
			*pserver = '@';
		return;
	}

	if (co->msgstate != OTRL_MSGSTATE_ENCRYPTED)
	{
		otr_notice (ircctx, nick, TXT_AUTH_NEEDENC);
		return;
	}

	coi = co->app_data;

	/* Aborting an ongoing auth */
	if (co->smstate->nextExpected != OTRL_SMP_EXPECT1)
		otr_abort_auth (co, ircctx, nick);

	coi->smp_failed = FALSE;

	/* reset trust level */
	if (co->active_fingerprint)
	{
		char *trust = co->active_fingerprint->trust;
		if (trust && (*trust != '\0'))
		{
			otrl_context_set_trust (co->active_fingerprint, "");
			otr_writefps ();
		}
	}

	if (!coi->received_smp_init)
		if (question)
			otrl_message_initiate_smp_q(
				otr_state,
				&otr_ops,
				ircctx,
				co,
				question,
				(unsigned char*)secret,
				strlen (secret));
		else
			otrl_message_initiate_smp (
				otr_state,
				&otr_ops,
				ircctx,
				co,
				(unsigned char *)secret,
				strlen (secret));
	else
		otrl_message_respond_smp (
			otr_state,
			&otr_ops,
			ircctx,
			co,
			(unsigned char *)secret,
			strlen (secret));

	otr_notice (ircctx, nick,
				coi->received_smp_init ? TXT_AUTH_RESPONDING : TXT_AUTH_INITIATED);

	statusbar_items_redraw ("otr");

	if (peername)
		*pserver = '@';
}

/*
 * Hand the given message to OTR.
 * Returns NULL if its an OTR protocol message and 
 * the (possibly) decrypted message otherwise.
 */
char *otr_receive (IRC_CTX *ircctx, const char *msg, const char *from)
{
	int ignore_message;
	char *newmessage = NULL;
	char accname[256];
	ConnContext *co;
	struct co_info *coi;
	OtrlTLV *tlvs;

	g_snprintf (accname, sizeof(accname), "%s@%s", IRCCTX_NICK (ircctx), IRCCTX_ADDR (ircctx));

	if (!(co = otr_getcontext (accname, from, TRUE, ircctx)))
	{
		otr_noticest (TXT_CTX_NOT_CREATE,
					  accname, from);
		return NULL;
	}

	coi = co->app_data;

	/* Really lame but I don't see how you could do this in a generic
	 * way unless the IRC server would somehow mark continuation messages.
	 */
	if ((strcmp (msg, coi->better_msg_two) == 0) || (strcmp (msg, formats[TXT_OTR_BETTER_THREE].def) == 0))
	{
		otr_debug (ircctx, from, TXT_RECEIVE_IGNORE_QUERY);
		return NULL;
	}

	/* The server might have split lines that were too long 
	 * (bitlbee does that). The heuristic is simple: If we can find ?OTR:
	 * in the message but it doesn't end with a ".", queue it and wait
	 * for the rest.
	 */
	if (coi->msgqueue)
	{ /* already something in the queue */
		g_strlcat (coi->msgqueue, msg, MSGQUEUE_LEN);

		/* wait for more? */
		if ((strlen (msg) > OTR_MAX_MSG_SIZE) && (msg[strlen (msg) - 1] != '.') && (msg[strlen (msg) - 1] != ','))
			return NULL;

		otr_debug (ircctx, from, TXT_RECEIVE_DEQUEUED,
				   strlen (coi->msgqueue));

		msg = coi->msgqueue;
		coi->msgqueue = NULL;

		/* this is freed thru our caller by otrl_message_free.
		 * Currently ok since that just uses free().
		 */
	}
	else if (strstr (msg, "?OTR:") && (strlen (msg) > OTR_MAX_MSG_SIZE) && (msg[strlen (msg) - 1] != '.') && (msg[strlen (msg) - 1] != ','))
	{
		coi->msgqueue = g_malloc (MSGQUEUE_LEN);
		g_strlcpy (coi->msgqueue, msg, MSGQUEUE_LEN);
		otr_debug (ircctx, from, TXT_RECEIVE_QUEUED, strlen (msg));
		return NULL;
	}

	ignore_message = otrl_message_receiving (
		otr_state,
		&otr_ops,
		ircctx,
		accname,
		PROTOCOLID,
		from,
		msg,
		&newmessage,
		&tlvs,
		&co,
		NULL,
		NULL);

	if (tlvs)
	{
		OtrlTLV *tlv = otrl_tlv_find (tlvs, OTRL_TLV_DISCONNECTED);
		if (tlv)
		{
			otr_status_change (ircctx, from, IO_STC_PEER_FINISHED);
			otr_notice (ircctx, from, TXT_PEER_FINISHED, from);
		}
	}

	if (ignore_message)
	{
		otr_debug (ircctx, from,
				   TXT_RECEIVE_IGNORE, strlen (msg), accname, from, msg);
		return NULL;
	}

	if (newmessage)
		otr_debug (ircctx, from, TXT_RECEIVE_CONVERTED);

	return newmessage ?: (char *)msg;
}

void otr_setpolicies (const char *policies, int known)
{
	GMatchInfo *match_info;
	GSList *plist = known ? plistknown : plistunknown;

	if (plist)
	{
		GSList *p = plist;
		do
		{
			struct plistentry *ple = p->data;
			g_pattern_spec_free (ple->namepat);
			g_free (p->data);
		} while ((p = g_slist_next (p)));

		g_slist_free (plist);
		plist = NULL;
	}

	g_regex_match (regex_policies, policies, 0, &match_info);

	while (g_match_info_matches (match_info))
	{
		struct plistentry *ple = (struct plistentry *)g_malloc0 (sizeof(struct plistentry));
		char *pol = g_match_info_fetch (match_info, 2);

		ple->namepat = g_pattern_spec_new (g_match_info_fetch (match_info, 1));

		switch (*pol)
		{
		case 'n':
			ple->policy = OTRL_POLICY_NEVER;
			break;
		case 'm':
			ple->policy = OTRL_POLICY_MANUAL;
			break;
		case 'h':
			ple->policy = OTRL_POLICY_MANUAL | OTRL_POLICY_WHITESPACE_START_AKE;
			break;
		case 'o':
			ple->policy = OTRL_POLICY_OPPORTUNISTIC;
			break;
		case 'a':
			ple->policy = OTRL_POLICY_ALWAYS;
			break;
		}

		plist = g_slist_append (plist, ple);

		g_free (pol);

		g_match_info_next (match_info, NULL);
	}

	g_match_info_free (match_info);

	if (known)
		plistknown = plist;
	else
		plistunknown = plist;
}

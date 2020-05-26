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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* OTR */

#include <libotr/proto.h>
#include <libotr/context.h>
#include <libotr/message.h>
#include <libotr/privkey.h>

/* glib */

#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

/* hexchat */

#include "hexchat_otr.h"

/* log stuff */

#define LOGMAX 1024

#define LVL_NOTICE 0
#define LVL_DEBUG 1

#define otr_logst(level, format, ...) \
	otr_log (NULL, NULL, level, format, ##__VA_ARGS__)

void otr_log (IRC_CTX *server, const char *to,
	      MessageLevel level, const char *format, ...);

/* own */

#include "config.h"

#include "otr-formats.h"

/* 
 * maybe this should be configurable?
 * I believe bitlbee has something >500.
 */
#define OTR_MAX_MSG_SIZE 400

/* otr protocol id */
#define PROTOCOLID "IRC"

#define KEYFILE "/otr/otr.key"
#define TMPKEYFILE "/otr/otr.key.tmp"
#define FPSFILE "/otr/otr.fp"
#define INSTAGFILE "/otr/otr.instag"

/* some defaults */
#define IO_DEFAULT_POLICY "*@localhost opportunistic,*bitlbee* opportunistic,*@im.* opportunistic, *serv@irc* never"
#define IO_DEFAULT_POLICY_KNOWN "* always"
#define IO_DEFAULT_IGNORE "xmlconsole[0-9]*"

static const char * const otr_msg_event_txt[] = {
	"NONE",
	"ENCRYPTION_REQUIRED",
	"ENCRYPTION_ERROR",
	"CONNECTION_ENDED",
	"SETUP_ERROR",
	"MSG_REFLECTED",
	"MSG_RESENT",
	"RCVDMSG_NOT_IN_PRIVATE",
	"RCVDMSG_UNREADABLE",
	"RCVDMSG_MALFORMED",
	"LOG_HEARTBEAT_RCVD",
	"LOG_HEARTBEAT_SENT",
	"RCVDMSG_GENERAL_ERR",
	"RCVDMSG_UNENCRYPTED",
	"RCVDMSG_UNRECOGNIZED",
	"RCVDMSG_FOR_OTHER_INSTANCE"
};

static const char * const otr_status_txt[] = {
	"FINISHED",
	"TRUST_MANUAL",
	"TRUST_SMP",
	"SMP_ABORT",
	"SMP_STARTED",
	"SMP_RESPONDED",
	"SMP_INCOMING",
	"SMP_FINALIZE",
	"SMP_ABORTED",
	"PEER_FINISHED",
	"SMP_FAILED",
	"SMP_SUCCESS",
	"GONE_SECURE",
	"GONE_INSECURE",
	"CTX_UPDATE"
};

/* returned by otr_getstatus */
enum {
	IO_ST_PLAINTEXT,
	IO_ST_FINISHED,
	IO_ST_SMP_INCOMING,
	IO_ST_SMP_OUTGOING,
	IO_ST_SMP_FINALIZE,
	IO_ST_UNKNOWN,
	IO_ST_UNTRUSTED=32,
	IO_ST_TRUST_MANUAL=64,
	IO_ST_TRUST_SMP=128,
	IO_ST_SMP_ONGOING= IO_ST_SMP_INCOMING|IO_ST_SMP_OUTGOING|IO_ST_SMP_FINALIZE
};

/* given to otr_status_change */
enum {
	IO_STC_FINISHED,
	IO_STC_TRUST_MANUAL,
	IO_STC_TRUST_SMP,
	IO_STC_SMP_ABORT,
	IO_STC_SMP_STARTED,
	IO_STC_SMP_RESPONDED,
	IO_STC_SMP_INCOMING,
	IO_STC_SMP_FINALIZE,
	IO_STC_SMP_ABORTED,
	IO_STC_PEER_FINISHED,
	IO_STC_SMP_FAILED,
	IO_STC_SMP_SUCCESS,
	IO_STC_GONE_SECURE,
	IO_STC_GONE_INSECURE,
	IO_STC_CTX_UPDATE
};

/* one for each OTR context (=communication pair) */
struct co_info
{
	char *msgqueue; /* holds partially reconstructed base64
					   messages */
	IRC_CTX *ircctx; /* irssi server object for this peer */
	int received_smp_init; /* received SMP init msg */
	int smp_failed; /* last SMP failed */
	char better_msg_two[256]; /* what the second line of the "better"
					   default query msg should like. Eat it
					   up when it comes in */
	int finished; /* true after you've /otr finished */
};

/* these are returned by /otr contexts */

struct fplist_
{
	char *fp;
	enum
	{
		NOAUTH,
		AUTHSMP,
		AUTHMAN
	} authby;
	struct fplist_ *next;
};

struct ctxlist_
{
	char *username;
	char *accountname;
	enum
	{
		STUNENCRYPTED,
		STENCRYPTED,
		STFINISHED,
		STUNKNOWN
	} state;
	struct fplist_ *fplist;
	struct ctxlist_ *next;
};

/* policy list generated from /set otr_policy */

struct plistentry
{
	GPatternSpec *namepat;
	OtrlPolicy policy;
};

/* used by the logging functions below */
extern int debug;

void irc_send_message (IRC_CTX *ircctx, const char *recipient, char *msg);
IRC_CTX *server_find_address (char *address);
void otr_status_change (IRC_CTX *ircctx, const char *nick, int event);

/* init stuff */

int otrlib_init (void);
void otrlib_deinit (void);
void otr_initops (void);
void otr_setpolicies (const char *policies, int known);

/* basic send/receive/status stuff */

char *otr_send (IRC_CTX *server, const char *msg, const char *to);
char *otr_receive (IRC_CTX *server, const char *msg, const char *from);
int otr_getstatus(IRC_CTX *ircctx, const char *nick);
ConnContext *otr_getcontext (const char *accname, const char *nick, int create, void *data);

/* user interaction */

void otr_trust (IRC_CTX *server, char *nick, const char *peername);
void otr_finish (IRC_CTX *server, char *nick, const char *peername, int inquery);
void otr_auth (IRC_CTX *server, char *nick, const char *peername, const char *question, const char *secret);
void otr_authabort (IRC_CTX *server, char *nick, const char *peername);
void otr_abort_auth(ConnContext *co, IRC_CTX *ircctx, const char *nick);
struct ctxlist_ *otr_contexts (void);
void otr_finishall (void);

/* key/fingerprint stuff */

void keygen_run (const char *accname);
void keygen_abort (int ignoreidle);
void key_load (void);
void fps_load (void);
void otr_writefps (void);

/* instance tags */
void instag_load (void);
void otr_writeinstags (void);

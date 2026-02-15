/*
 *  m_sasl.c - SASL authentication module for ircd-hybrid 8.2.x
 *
 *  Implements SASL (RFC 4422) via IRCv3 CAP + AUTHENTICATE + ENCAP relay
 *  to Anope IRC Services (or any services supporting ENCAP SASL).
 *
 *  Copyright (c) 2026 Chatik IRC Network
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "stdinc.h"
#include "module.h"
#include "cap.h"
#include "client.h"
#include "hash.h"
#include "id.h"
#include "ircd.h"
#include "ircd_hook.h"
#include "numeric.h"
#include "parse.h"
#include "send.h"
#include "io_string.h"
#include "io_time.h"


/* SASL capability flag - next available bit after CAP_STANDARD_REPLIES (1 << 8) */
#define CAP_SASL (1 << 9)

/* Limits */
#define SASL_MAX_SESSIONS  256
#define SASL_MAX_MESSAGES   20
#define SASL_MAX_FAILURES    3

/*
 * SASL session state — tracks each in-progress SASL negotiation.
 * Sessions are keyed by client pointer and cleaned up on client exit.
 */
struct sasl_session
{
  struct Client *client;         /* The local client performing SASL */
  char agent[IDLEN + 1];        /* UID of the services agent handling this session */
  unsigned int messages;         /* Number of AUTHENTICATE messages received */
  unsigned int failures;         /* Number of failed authentication attempts */
  uintmax_t start_time;         /* Monotonic time when session started */
  bool complete;                 /* True once D (done) received from services */
};

static struct sasl_session sessions[SASL_MAX_SESSIONS];


/* ----------------------------------------------------------------
 * Session management helpers
 * ---------------------------------------------------------------- */

static struct sasl_session *
sasl_find_session(const struct Client *client)
{
  for (unsigned int i = 0; i < SASL_MAX_SESSIONS; ++i)
    if (sessions[i].client == client)
      return &sessions[i];
  return NULL;
}

static struct sasl_session *
sasl_new_session(struct Client *client)
{
  for (unsigned int i = 0; i < SASL_MAX_SESSIONS; ++i)
  {
    if (sessions[i].client == NULL)
    {
      memset(&sessions[i], 0, sizeof(sessions[i]));
      sessions[i].client = client;
      sessions[i].start_time = io_time_get(IO_TIME_MONOTONIC_SEC);
      return &sessions[i];
    }
  }
  return NULL;
}

static void
sasl_clear_session(struct sasl_session *session)
{
  memset(session, 0, sizeof(*session));
}


/* ----------------------------------------------------------------
 * Hook: clean up session when a local client exits
 * ---------------------------------------------------------------- */

static hook_flow_t
sasl_client_exit_hook(void *data)
{
  const ircd_hook_client_exit_ctx *ctx = data;
  struct sasl_session *session = sasl_find_session(ctx->client);

  if (session)
  {
    /* Notify services of the abort if we know the agent */
    if (session->agent[0] && ctx->client->id[0])
      sendto_servers(NULL, 0, 0, ":%s ENCAP * SASL %s %s D A",
                     me.id, ctx->client->id, session->agent);
    sasl_clear_session(session);
  }

  return HOOK_FLOW_CONTINUE;
}


/* ----------------------------------------------------------------
 * AUTHENTICATE command handler (unregistered clients only)
 *
 * Flow:
 *   1. Client sends  AUTHENTICATE PLAIN         (mechanism selection)
 *   2. Module sends   ENCAP * SASL uid * H host ip  (host info to services)
 *   3. Module sends   ENCAP * SASL uid * S PLAIN    (start auth)
 *   4. Services sends ENCAP sid SASL agent uid C +   (request credentials)
 *   5. Module relays  AUTHENTICATE +                 (to client)
 *   6. Client sends  AUTHENTICATE base64data        (credentials)
 *   7. Module sends   ENCAP * SASL uid agent C b64   (relay to services)
 *   8. Services sends ENCAP sid SVSLOGIN uid ...      (set account)
 *   9. Services sends ENCAP sid SASL agent uid D S    (success)
 *  10. Module sends   900 + 903 to client
 * ---------------------------------------------------------------- */

static void
mr_authenticate(struct Client *source, int parc, char *parv[])
{
  /* Client must have requested sasl capability */
  if (!HasCap(source, CAP_SASL))
    return;

  /* AUTHENTICATE * = abort current SASL session */
  if (strcmp(parv[1], "*") == 0)
  {
    struct sasl_session *session = sasl_find_session(source);

    if (session)
    {
      if (session->agent[0] && source->id[0])
        sendto_servers(NULL, 0, 0, ":%s ENCAP * SASL %s %s D A",
                       me.id, source->id, session->agent);
      sasl_clear_session(session);
    }

    sendto_one_numeric(source, &me, 906 | SND_EXPLICIT,
                       "%s :SASL authentication aborted", source->name);
    return;
  }

  /* Assign a UID early so services can reference this client.
   * The user.c patch prevents user_register_local() from overwriting this. */
  if (source->id[0] == '\0')
  {
    const char *id;
    while (hash_find_id((id = uid_get())))
      ;
    strlcpy(source->id, id, sizeof(source->id));
    hash_add_id(source);
  }

  struct sasl_session *session = sasl_find_session(source);

  if (session == NULL)
  {
    /* New SASL session — mechanism selection */
    session = sasl_new_session(source);
    if (session == NULL)
    {
      sendto_one_numeric(source, &me, 904 | SND_EXPLICIT,
                         "%s :SASL authentication failed", source->name);
      return;
    }

    /* Send client host/IP info to services (H command) */
    sendto_servers(NULL, 0, 0, ":%s ENCAP * SASL %s * H %s %s",
                   me.id, source->id, source->host, source->sockhost);

    /* Send mechanism start (S command) */
    sendto_servers(NULL, 0, 0, ":%s ENCAP * SASL %s * S %s",
                   me.id, source->id, parv[1]);
  }
  else
  {
    /* Continuation — relay client data to services (C command) */
    if (++session->messages > SASL_MAX_MESSAGES)
    {
      sendto_one_numeric(source, &me, 904 | SND_EXPLICIT,
                         "%s :SASL message limit exceeded", source->name);

      if (session->agent[0])
        sendto_servers(NULL, 0, 0, ":%s ENCAP * SASL %s %s D A",
                       me.id, source->id, session->agent);
      sasl_clear_session(session);
      return;
    }

    sendto_servers(NULL, 0, 0, ":%s ENCAP * SASL %s %s C %s",
                   me.id, source->id,
                   session->agent[0] ? session->agent : "*",
                   parv[1]);
  }
}


/* ----------------------------------------------------------------
 * SASL ENCAP handler — responses from services
 *
 * Received via ENCAP dispatch (m_encap.c strips ENCAP + target):
 *   parv[0] = "SASL"
 *   parv[1] = agent UID (services)
 *   parv[2] = target UID (our client)
 *   parv[3] = type: C (client data), D (done), L (login), M (mechs)
 *   parv[4] = data (base64, "S"/"F" for D type, account for L, etc.)
 * ---------------------------------------------------------------- */

static void
me_sasl(struct Client *source, int parc, char *parv[])
{
  struct Client *target = hash_find_id(parv[2]);
  if (target == NULL || !MyConnect(target))
    return;

  struct sasl_session *session = sasl_find_session(target);

  switch (parv[3][0])
  {
    case 'C':  /* Client data — relay to local client */
      if (parc < 5)
        break;

      sendto_one(target, "AUTHENTICATE %s", parv[4]);

      /* Remember the agent UID for future relay messages */
      if (session && session->agent[0] == '\0')
        strlcpy(session->agent, parv[1], sizeof(session->agent));
      break;

    case 'D':  /* Done — authentication result */
      if (parc >= 5 && parv[4][0] == 'S')
      {
        /* Success */
        sendto_one_numeric(target, &me, 900 | SND_EXPLICIT,
                           "%s %s!%s@%s %s :You are now logged in as %s",
                           target->name,
                           target->name, target->username, target->host,
                           target->account, target->account);
        sendto_one_numeric(target, &me, 903 | SND_EXPLICIT,
                           "%s :SASL authentication successful",
                           target->name);

        if (session)
        {
          session->complete = true;
          sasl_clear_session(session);
        }
      }
      else
      {
        /* Failure */
        unsigned int failures = 0;

        if (session)
        {
          failures = ++session->failures;

          if (failures >= SASL_MAX_FAILURES)
          {
            sendto_one_numeric(target, &me, 904 | SND_EXPLICIT,
                               "%s :SASL authentication failed",
                               target->name);
            sasl_clear_session(session);
            break;
          }
        }

        sendto_one_numeric(target, &me, 904 | SND_EXPLICIT,
                           "%s :SASL authentication failed",
                           target->name);
      }
      break;

    case 'L':  /* Login — set account name on client */
      if (parc >= 5)
        strlcpy(target->account, parv[4], sizeof(target->account));
      break;

    case 'M':  /* Mechanism list update */
    {
      const char *mechs = (parc >= 5 && !string_is_empty(parv[4])) ? parv[4] : NULL;
      cap_unregister("sasl");
      cap_register(CAP_SASL, "sasl", mechs);
      break;
    }
  }
}


/* ----------------------------------------------------------------
 * SVSLOGIN ENCAP handler — account set from services
 *
 * After ENCAP dispatch:
 *   parv[0] = "SVSLOGIN"
 *   parv[1] = target UID
 *   parv[2] = nick (or "*" = unchanged)
 *   parv[3] = ident (or "*" = unchanged)
 *   parv[4] = vhost (or "*" = unchanged)
 *   parv[5] = account
 * ---------------------------------------------------------------- */

static void
me_svslogin(struct Client *source, int parc, char *parv[])
{
  if (!HasFlag(source, FLAGS_SERVICE) && !IsServer(source))
    return;

  struct Client *target = hash_find_id(parv[1]);
  if (target == NULL)
    return;

  /* Set account name */
  if (parc >= 6 && strcmp(parv[5], "*") != 0)
    strlcpy(target->account, parv[5], sizeof(target->account));

  /* Set vhost if provided */
  if (parc >= 5 && strcmp(parv[4], "*") != 0)
    strlcpy(target->host, parv[4], sizeof(target->host));

  /* Set ident if provided */
  if (parc >= 4 && strcmp(parv[3], "*") != 0)
    strlcpy(target->username, parv[3], sizeof(target->username));
}


/* ----------------------------------------------------------------
 * MECHLIST ENCAP handler — mechanism list update from services
 *
 * After ENCAP dispatch:
 *   parv[0] = "MECHLIST"
 *   parv[1] = space-separated mechanism list (e.g. "PLAIN EXTERNAL")
 * ---------------------------------------------------------------- */

static void
me_mechlist(struct Client *source, int parc, char *parv[])
{
  const char *mechs = (parc >= 2 && !string_is_empty(parv[1])) ? parv[1] : NULL;
  cap_unregister("sasl");
  cap_register(CAP_SASL, "sasl", mechs);
}


/* ----------------------------------------------------------------
 * Command tables
 * ---------------------------------------------------------------- */

static struct Command authenticate_cmd =
{
  .name = "AUTHENTICATE",
  .handlers[UNREGISTERED_HANDLER] = { .handler = mr_authenticate, .args_min = 2 },
  .handlers[CLIENT_HANDLER] = { .handler = m_registered },
  .handlers[SERVER_HANDLER] = { .handler = m_ignore },
  .handlers[ENCAP_HANDLER] = { .handler = m_ignore },
  .handlers[OPER_HANDLER] = { .handler = m_registered },
};

static struct Command sasl_cmd =
{
  .name = "SASL",
  .handlers[UNREGISTERED_HANDLER] = { .handler = m_ignore },
  .handlers[CLIENT_HANDLER] = { .handler = m_ignore },
  .handlers[SERVER_HANDLER] = { .handler = m_ignore },
  .handlers[ENCAP_HANDLER] = { .handler = me_sasl, .args_min = 4 },
  .handlers[OPER_HANDLER] = { .handler = m_ignore },
};

static struct Command svslogin_cmd =
{
  .name = "SVSLOGIN",
  .handlers[UNREGISTERED_HANDLER] = { .handler = m_ignore },
  .handlers[CLIENT_HANDLER] = { .handler = m_ignore },
  .handlers[SERVER_HANDLER] = { .handler = m_ignore },
  .handlers[ENCAP_HANDLER] = { .handler = me_svslogin, .args_min = 2 },
  .handlers[OPER_HANDLER] = { .handler = m_ignore },
};

static struct Command mechlist_cmd =
{
  .name = "MECHLIST",
  .handlers[UNREGISTERED_HANDLER] = { .handler = m_ignore },
  .handlers[CLIENT_HANDLER] = { .handler = m_ignore },
  .handlers[SERVER_HANDLER] = { .handler = m_ignore },
  .handlers[ENCAP_HANDLER] = { .handler = me_mechlist, .args_min = 1 },
  .handlers[OPER_HANDLER] = { .handler = m_ignore },
};


/* ----------------------------------------------------------------
 * Module init / exit
 * ---------------------------------------------------------------- */

static void
init_handler(void)
{
  cap_register(CAP_SASL, "sasl", "PLAIN");
  command_add(&authenticate_cmd);
  command_add(&sasl_cmd);
  command_add(&svslogin_cmd);
  command_add(&mechlist_cmd);
  hook_install(ircd_hook_client_exit_local, sasl_client_exit_hook, HOOK_PRIORITY_DEFAULT);
}

static void
exit_handler(void)
{
  cap_unregister("sasl");
  command_del(&authenticate_cmd);
  command_del(&sasl_cmd);
  command_del(&svslogin_cmd);
  command_del(&mechlist_cmd);
  hook_uninstall(ircd_hook_client_exit_local, sasl_client_exit_hook);
  memset(sessions, 0, sizeof(sessions));
}

struct Module module_entry =
{
  .init_handler = init_handler,
  .exit_handler = exit_handler,
};

/*
 * ns_force_prefix - Force ~ prefix on unregistered nicknames
 *
 * This module forces all unregistered users to have a ~ prefix
 * on their nickname. When a user identifies with NickServ, the
 * prefix is removed and they get their original nick back.
 *
 * Copyright (C) 2026 Chatik / d00f
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "module.h"

static const char PREFIX_CHAR = '~';

class NSForcePrefix final
	: public Module
{
private:
	/* Check if a nick is registered */
	bool IsRegistered(const Anope::string &nick)
	{
		NickAlias *na = NickAlias::Find(nick);
		return na && na->nc;
	}

	/* Check if user is already identified */
	bool IsIdentified(User *u)
	{
		return u->Account() != nullptr;
	}

	/* Apply ~ prefix to user if needed */
	void ApplyPrefix(User *u)
	{
		if (!u || u->Quitting())
			return;

		/* Don't touch services or U-lined servers */
		if (!u->server || u->server->IsULined())
			return;

		/* Don't touch already identified users */
		if (IsIdentified(u))
			return;

		const Anope::string &nick = u->nick;

		/* Already has prefix */
		if (!nick.empty() && nick[0] == PREFIX_CHAR)
			return;

		/* Nick is registered — don't prefix; nick protection will handle it */
		if (IsRegistered(nick))
			return;

		/* Check IRCd support */
		if (!IRCD || !IRCD->CanSVSNick)
			return;

		Anope::string newNick = Anope::string(1, PREFIX_CHAR) + nick;

		/* Truncate if too long */
		if (IRCD->MaxNick && newNick.length() > IRCD->MaxNick)
			newNick = newNick.substr(0, IRCD->MaxNick);

		/* Check if new nick is valid and not taken */
		if (!IRCD->IsNickValid(newNick))
			return;

		/* Don't force to ~nick if ~nick itself is registered */
		if (IsRegistered(newNick))
			return;

		User *existing = User::Find(newNick, true);
		if (existing && existing != u)
		{
			/* ~nick already taken, nothing we can do */
			return;
		}

		Log(LOG_DEBUG) << "ns_force_prefix: Changing " << nick << " to " << newNick;
		IRCD->SendForceNickChange(u, newNick, Anope::CurTime);
	}

public:
	NSForcePrefix(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
	{
		this->SetAuthor("d00f");
		this->SetVersion("1.0.0");
	}

	/* User connects to IRC */
	void OnUserConnect(User *u, bool &exempt) override
	{
		if (!u || u->Quitting() || !u->server || !u->server->IsSynced())
			return;

		ApplyPrefix(u);
	}

	/* User changes nick */
	void OnUserNickChange(User *u, const Anope::string &oldnick) override
	{
		if (!u || u->Quitting())
			return;

		ApplyPrefix(u);
	}

	/* User identifies with NickServ — remove prefix */
	void OnNickIdentify(User *u) override
	{
		if (!u || u->Quitting())
			return;

		const Anope::string &nick = u->nick;

		/* Only act if nick starts with ~ */
		if (nick.empty() || nick[0] != PREFIX_CHAR)
			return;

		Anope::string originalNick = nick.substr(1);

		/* Check that the original nick belongs to the account they identified to */
		NickAlias *na = NickAlias::Find(originalNick);
		if (!na || !na->nc || na->nc != u->Account())
			return;

		/* Check IRCd support */
		if (!IRCD || !IRCD->CanSVSNick)
			return;

		/* Check if original nick is available */
		User *existing = User::Find(originalNick, true);
		if (existing && existing != u)
		{
			/* Someone else has the original nick */
			return;
		}

		Log(LOG_DEBUG) << "ns_force_prefix: Restoring " << nick << " to " << originalNick;
		IRCD->SendForceNickChange(u, originalNick, Anope::CurTime);
	}

	/* Also handle login (e.g. SASL auto-identify) */
	void OnUserLogin(User *u) override
	{
		if (!u || u->Quitting())
			return;

		const Anope::string &nick = u->nick;

		/* Only act if nick starts with ~ */
		if (nick.empty() || nick[0] != PREFIX_CHAR)
			return;

		Anope::string originalNick = nick.substr(1);

		NickAlias *na = NickAlias::Find(originalNick);
		if (!na || !na->nc || na->nc != u->Account())
			return;

		if (!IRCD || !IRCD->CanSVSNick)
			return;

		User *existing = User::Find(originalNick, true);
		if (existing && existing != u)
			return;

		Log(LOG_DEBUG) << "ns_force_prefix: Restoring (login) " << nick << " to " << originalNick;
		IRCD->SendForceNickChange(u, originalNick, Anope::CurTime);
	}
};

MODULE_INIT(NSForcePrefix)

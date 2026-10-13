/************************************************************************
 *   IRC - Internet Relay Chat, ircd/s_callerid.c
 *
 *   Caller-ID (user modes +g and +G, the ACCEPT command) and the
 *   automatic private-message flood shield.  See doc/callerid.txt.
 *
 *   Everything here is local to this server: the modes are never sent
 *   to other servers, and messages are checked when they arrive for a
 *   user connected here, wherever the sender is on the network.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */

#include "os.h"
#include "s_defines.h"
#define S_CALLERID_C
#include "s_externs.h"
#undef S_CALLERID_C

#ifdef CALLERID

#ifndef CALLERID_MAXACCEPT
# define CALLERID_MAXACCEPT	30
#endif
#ifndef CALLERID_NOTIFY_INTERVAL
# define CALLERID_NOTIFY_INTERVAL 60
#endif
#ifndef FLOOD_SHIELD_SENDERS
# define FLOOD_SHIELD_SENDERS	20
#endif
#ifndef FLOOD_SHIELD_WINDOW
# define FLOOD_SHIELD_WINDOW	10
#endif
#ifndef FLOOD_SHIELD_TIME
# define FLOOD_SHIELD_TIME	300
#endif
#if FLOOD_SHIELD_SENDERS > 64
# error FLOOD_SHIELD_SENDERS must not be bigger than 64
#endif

#define	CID_NOTIFIED	16	/* senders remembered for the 716 rate limit */
#define	CID_SENDERS	64	/* senders remembered for the shield */

typedef	struct	{
	char	uid[UIDLEN+1];
	time_t	t;
} cidSender;

/* per local user state, allocated on first use */
struct	CallerID {
	time_t	last_notice;	/* last 718 sent to this user */
	time_t	shield_until;	/* flood shield active until */
	long	shield_blocked;	/* messages blocked during the shield */
	int	next_notified;
	cidSender notified[CID_NOTIFIED];	/* senders told 716 */
	int	next_sender;
	cidSender senders[CID_SENDERS];		/* recent distinct senders */
};

time_t	nextshieldcheck = 0;

static	struct CallerID *cid_state(aClient *cptr)
{
	if (!cptr->user->cid)
	{
		cptr->user->cid = (struct CallerID *)
			MyMalloc(sizeof(struct CallerID));
		bzero((char *)cptr->user->cid, sizeof(struct CallerID));
	}
	return cptr->user->cid;
}

static	int	shield_active(aClient *cptr)
{
	return cptr->user->cid && cptr->user->cid->shield_until > timeofday;
}

static	Link	*find_cptr_link(Link *lp, aClient *cptr)
{
	for (; lp; lp = lp->next)
		if (lp->value.cptr == cptr)
			return lp;
	return NULL;
}

static	int	count_links(Link *lp)
{
	int	n = 0;

	for (; lp; lp = lp->next)
		n++;
	return n;
}

static	void	del_cptr_link(Link **lpp, aClient *cptr)
{
	Link	*lp;

	for (; (lp = *lpp); lpp = &lp->next)
		if (lp->value.cptr == cptr)
		{
			*lpp = lp->next;
			free_link(lp);
			return;
		}
}

static	void	add_cptr_link(Link **lpp, aClient *cptr)
{
	Link	*lp = make_link();

	lp->value.cptr = cptr;
	lp->flags = 0;
	lp->next = *lpp;
	*lpp = lp;
}

/* does local user 'me_' accept messages from 'who'? */
static	int	accepts(aClient *me_, aClient *who)
{
	return find_cptr_link(me_->user->accepts, who) != NULL;
}

/* 0 = added, 1 = already there, -1 = list full */
static	int	add_accept(aClient *me_, aClient *who)
{
	if (accepts(me_, who))
		return 1;
	if (count_links(me_->user->accepts) >= CALLERID_MAXACCEPT)
		return -1;
	add_cptr_link(&me_->user->accepts, who);
	add_cptr_link(&who->user->accepted_by, me_);
	return 0;
}

static	int	del_accept(aClient *me_, aClient *who)
{
	if (!accepts(me_, who))
		return -1;
	del_cptr_link(&me_->user->accepts, who);
	del_cptr_link(&who->user->accepted_by, me_);
	return 0;
}

/*
 * Remember 'uid' in a small table; returns 1 if it was already there and
 * younger than 'maxage' seconds.
 */
static	int	seen_recently(cidSender *tab, int size, int *next,
			char *uid, int maxage)
{
	int	i;

	for (i = 0; i < size; i++)
		if (tab[i].t && timeofday - tab[i].t < maxage &&
		    !strcmp(tab[i].uid, uid))
			return 1;
	strncpyzt(tab[*next].uid, uid, sizeof(tab[*next].uid));
	tab[*next].t = timeofday;
	*next = (*next + 1) % size;
	return 0;
}

static	int	count_recent(cidSender *tab, int size, int maxage)
{
	int	i, n = 0;

	for (i = 0; i < size; i++)
		if (tab[i].t && timeofday - tab[i].t < maxage)
			n++;
	return n;
}

/*
 * Count distinct senders hitting 'target'; switch the shield on (or
 * extend it) when FLOOD_SHIELD_SENDERS of them arrive within
 * FLOOD_SHIELD_WINDOW seconds.
 */
static	void	shield_count(aClient *sptr, aClient *target)
{
#if FLOOD_SHIELD_SENDERS > 0
	struct	CallerID *cid = cid_state(target);
	int	n, was_active = shield_active(target);

	if (seen_recently(cid->senders, CID_SENDERS, &cid->next_sender,
		sptr->user->uid, FLOOD_SHIELD_WINDOW))
		return;
	n = count_recent(cid->senders, CID_SENDERS, FLOOD_SHIELD_WINDOW);
	if (n < FLOOD_SHIELD_SENDERS)
		return;

	cid->shield_until = timeofday + FLOOD_SHIELD_TIME;
	if (!nextshieldcheck || nextshieldcheck > cid->shield_until)
		nextshieldcheck = cid->shield_until;
	if (was_active)
		return;		/* still flooded: just extended */

	cid->shield_blocked = 0;
	sendto_one(target, ":%s NOTICE %s :*** Flood protection activated: "
		"%d different users messaged you within %d seconds. For the "
		"next %d minutes only users on your ACCEPT list (and IRC "
		"operators) can message you. Use /ACCEPT nick to allow "
		"someone.", ME, target->name, n, FLOOD_SHIELD_WINDOW,
		(FLOOD_SHIELD_TIME + 59) / 60);
	sendto_flag(SCH_NOTICE, "Flood shield activated for %s (%d senders "
		"in %ds), e.g. %s!%s@%s from %s", target->name, n,
		FLOOD_SHIELD_WINDOW, sptr->name, sptr->user->username,
		sptr->user->host, sptr->user->server);
#endif
}

/*
 * Called for every PRIVMSG/NOTICE addressed to a user.
 * Returns 1 if the message may be delivered, 0 if it must be dropped.
 */
int	callerid_check(aClient *sptr, aClient *target, int notice)
{
	struct	CallerID *cid;
	int	blocking, silent;

	if (!MyConnect(target) || !target->user || sptr == target)
		return 1;
	/* servers, services and operators always get through */
	if (!IsPerson(sptr) || !sptr->user || IsAnOper(sptr))
		return 1;
	if (accepts(target, sptr))
		return 1;

	shield_count(sptr, target);

	blocking = (target->user->flags & (FLAGS_CALLERID|FLAGS_CALLERIDS))
		|| shield_active(target);
	if (!blocking)
		return 1;

	cid = cid_state(target);
	silent = (target->user->flags & FLAGS_CALLERIDS) ||
		shield_active(target);

	if (shield_active(target))
	{
		cid->shield_blocked++;
		return 0;	/* the shield is always silent */
	}

	/* tell the sender, at most once per interval per target */
	if (!silent && !notice &&
	    !seen_recently(cid->notified, CID_NOTIFIED, &cid->next_notified,
		sptr->user->uid, CALLERID_NOTIFY_INTERVAL))
	{
		sendto_one(sptr, replies[ERR_TARGUMODEG], ME, sptr->name,
			target->name);
		sendto_one(sptr, replies[RPL_TARGNOTIFY], ME, sptr->name,
			target->name);
	}

#ifdef CALLERID_TARGET_NOTICE
	/* tell the target, at most once per interval in total */
	if (timeofday - cid->last_notice >= CALLERID_NOTIFY_INTERVAL)
	{
		cid->last_notice = timeofday;
		sendto_one(target, replies[RPL_UMODEGMSG], ME, target->name,
			sptr->name, sptr->user->username, sptr->user->host);
	}
#endif
	return 0;
}

/*
 * A +g/+G user who sends a PRIVMSG to someone accepts their replies.
 */
void	callerid_sent(aClient *sptr, aClient *target)
{
	if (!MyConnect(sptr) || !sptr->user || !target->user ||
	    sptr == target || !IsPerson(target))
		return;
	if (!(sptr->user->flags & (FLAGS_CALLERID|FLAGS_CALLERIDS)) &&
	    !shield_active(sptr))
		return;
	(void)add_accept(sptr, target);
}

/* remove every reference to a user that is leaving the network */
void	callerid_exit(aClient *cptr)
{
	Link	*lp, *next;

	if (!cptr->user)
		return;
	for (lp = cptr->user->accepted_by; lp; lp = next)
	{
		next = lp->next;
		del_cptr_link(&lp->value.cptr->user->accepts, cptr);
		free_link(lp);
	}
	cptr->user->accepted_by = NULL;
	for (lp = cptr->user->accepts; lp; lp = next)
	{
		next = lp->next;
		del_cptr_link(&lp->value.cptr->user->accepted_by, cptr);
		free_link(lp);
	}
	cptr->user->accepts = NULL;
	if (cptr->user->cid)
	{
		MyFree(cptr->user->cid);
		cptr->user->cid = NULL;
	}
}

/* end expired shields; returns the time of the next check (0 = none) */
time_t	callerid_expire(time_t now)
{
	int	i;
	aClient	*acptr;
	struct	CallerID *cid;
	time_t	next = 0;

	for (i = highest_fd; i >= 0; i--)
	{
		if (!(acptr = local[i]) || !IsPerson(acptr) ||
		    !(cid = acptr->user->cid) || !cid->shield_until)
			continue;
		if (cid->shield_until > now)
		{
			if (!next || cid->shield_until < next)
				next = cid->shield_until;
			continue;
		}
		cid->shield_until = 0;
		sendto_one(acptr, ":%s NOTICE %s :*** Flood protection ended. "
			"%ld private message%s blocked.", ME, acptr->name,
			cid->shield_blocked, cid->shield_blocked == 1 ?
			" was" : "s were");
	}
	return next;
}

/*
 * ACCEPT [nick,nick,-nick,...]	add or remove
 * ACCEPT *			list (also with no parameter)
 */
int	m_accept(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	char	*p = NULL, *nick, *list;
	aClient	*acptr;
	Link	*lp;
	char	lbuf[BUFSIZE];
	int	del, len;

	if (!MyConnect(sptr) || !sptr->user)
		return 0;

	if (parc < 2 || BadPtr(parv[1]) || !strcmp(parv[1], "*"))
	{
		lbuf[0] = '\0';
		len = 0;
		for (lp = sptr->user->accepts; lp; lp = lp->next)
		{
			if (len + strlen(lp->value.cptr->name) + 2 > 400)
			{
				sendto_one(sptr, replies[RPL_ACCEPTLIST], ME,
					sptr->name, lbuf);
				lbuf[0] = '\0';
				len = 0;
			}
			if (len)
				lbuf[len++] = ' ';
			strcpy(lbuf + len, lp->value.cptr->name);
			len += strlen(lp->value.cptr->name);
		}
		if (len)
			sendto_one(sptr, replies[RPL_ACCEPTLIST], ME,
				sptr->name, lbuf);
		sendto_one(sptr, replies[RPL_ENDOFACCEPT], ME, sptr->name);
		return 1;
	}

	list = parv[1];
	for (nick = strtoken(&p, list, ","); nick;
	     nick = strtoken(&p, NULL, ","))
	{
		del = (*nick == '-');
		if (del)
			nick++;
		if (!*nick)
			continue;
		if (!(acptr = find_person(nick, NULL)) || !acptr->user)
		{
			sendto_one(sptr, replies[ERR_NOSUCHNICK], ME,
				sptr->name, nick);
			continue;
		}
		if (del)
		{
			if (del_accept(sptr, acptr) < 0)
				sendto_one(sptr, replies[ERR_ACCEPTNOT], ME,
					sptr->name, acptr->name);
			continue;
		}
		switch (add_accept(sptr, acptr))
		{
		case 1:
			sendto_one(sptr, replies[ERR_ACCEPTEXIST], ME,
				sptr->name, acptr->name);
			break;
		case -1:
			sendto_one(sptr, replies[ERR_ACCEPTFULL], ME,
				sptr->name);
			return 1;
		}
	}
	return 1;
}

#endif /* CALLERID */

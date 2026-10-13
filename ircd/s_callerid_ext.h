/************************************************************************
 *   IRC - Internet Relay Chat, ircd/s_callerid_ext.h
 *
 *   External definitions for functions defined in ircd/s_callerid.c.
 */

#ifndef S_CALLERID_C
#define EXTERN extern
#else /* S_CALLERID_C */
#define EXTERN
#endif /* S_CALLERID_C */
#ifdef	CALLERID
EXTERN time_t nextshieldcheck;
EXTERN int callerid_check (aClient *sptr, aClient *target, int notice);
EXTERN void callerid_sent (aClient *sptr, aClient *target);
EXTERN void callerid_exit (aClient *cptr);
EXTERN time_t callerid_expire (time_t now);
EXTERN int m_accept (aClient *cptr, aClient *sptr, int parc, char *parv[]);
#endif /* CALLERID */
#undef EXTERN

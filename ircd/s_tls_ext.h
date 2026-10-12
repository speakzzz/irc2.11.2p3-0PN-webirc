/************************************************************************
 *   IRC - Internet Relay Chat, ircd/s_tls_ext.h
 *
 *   External definitions for functions defined in ircd/s_tls.c.
 */

#ifndef S_TLS_C
#define EXTERN extern
#else /* S_TLS_C */
#define EXTERN
#endif /* S_TLS_C */
#ifdef	USE_SSL
EXTERN int tls_init (int startup);
EXTERN int tls_accept (aClient *cptr, int fd);
EXTERN int tls_read (aClient *cptr, char *buf, int len);
EXTERN int tls_write (aClient *cptr, char *buf, int len);
EXTERN int tls_writable (aClient *cptr);
EXTERN int tls_want_write (aClient *cptr);
EXTERN char *tls_error (void);
EXTERN void tls_close (aClient *cptr);
EXTERN void tls_free (aClient *cptr);
EXTERN char *tls_cipher (aClient *cptr);
#endif /* USE_SSL */
EXTERN int certfp_match (char *have, char *conf);
EXTERN int conf_certfp (aClient *cptr, char *confpass, char **rest, int *ok);
#undef EXTERN

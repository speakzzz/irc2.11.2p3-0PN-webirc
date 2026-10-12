/************************************************************************
 *   IRC - Internet Relay Chat, ircd/s_tls.c
 *
 *   Native TLS for client ports (P-lines with the 'E' flag) and client
 *   certificate fingerprints (CertFP).  See doc/tls.txt.
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
#define S_TLS_C
#include "s_externs.h"
#undef S_TLS_C

#ifdef USE_SSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#ifndef TLS_CERT_FILE
# define TLS_CERT_FILE	"ircd.crt"
#endif
#ifndef TLS_KEY_FILE
# define TLS_KEY_FILE	"ircd.key"
#endif

static	SSL_CTX	*tls_ctx = NULL;
static	char	tls_errbuf[256];

/* last OpenSSL error as text; clears the error queue */
static	char	*tls_lasterr(void)
{
	unsigned long	e = ERR_get_error();

	if (e)
		ERR_error_string_n(e, tls_errbuf, sizeof(tls_errbuf));
	else
		strcpy(tls_errbuf, "unknown error");
	ERR_clear_error();
	return tls_errbuf;
}

/* accept any client certificate: it is only used for its fingerprint */
static	int	tls_verify_cb(int ok, X509_STORE_CTX *store)
{
	return 1;
}

static	SSL_CTX	*tls_make_ctx(char **err)
{
	SSL_CTX	*ctx;
	static	const unsigned char sid_ctx[] = "ircd";

	if (!(ctx = SSL_CTX_new(TLS_server_method())))
	{
		*err = tls_lasterr();
		return NULL;
	}
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE |
		SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION
#ifdef SSL_OP_NO_RENEGOTIATION
		| SSL_OP_NO_RENEGOTIATION
#endif
		);
	/* ircd's send queue may move and is written in pieces */
	SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx) - 1);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	SSL_CTX_set_num_tickets(ctx, 0);
#endif
#ifdef TLS_CIPHERS
	if (!SSL_CTX_set_cipher_list(ctx, TLS_CIPHERS))
	{
		*err = tls_lasterr();
		SSL_CTX_free(ctx);
		return NULL;
	}
#endif
	/* ask for a client certificate, never require one */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
		tls_verify_cb);

	if (SSL_CTX_use_certificate_chain_file(ctx, TLS_CERT_FILE) != 1 ||
	    SSL_CTX_use_PrivateKey_file(ctx, TLS_KEY_FILE,
		SSL_FILETYPE_PEM) != 1 ||
	    SSL_CTX_check_private_key(ctx) != 1)
	{
		*err = tls_lasterr();
		SSL_CTX_free(ctx);
		return NULL;
	}
	return ctx;
}

/* are any P-lines configured with the E flag? */
static	int	tls_ports_configured(void)
{
	aConfItem	*aconf;

	for (aconf = conf; aconf; aconf = aconf->next)
		if ((aconf->status & CONF_LISTEN_PORT) && IsConfSSL(aconf))
			return 1;
	return 0;
}

/*
 * (Re)load certificate and key.  On startup a failure is fatal when TLS
 * ports are configured.  On rehash the old context is kept on failure,
 * so a broken renewal does not take the TLS ports down.
 */
int	tls_init(int startup)
{
	SSL_CTX	*ctx;
	char	*err = NULL;

	if (startup)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		SSL_library_init();
		SSL_load_error_strings();
#endif
	}
	if (!(ctx = tls_make_ctx(&err)))
	{
		if (startup && tls_ports_configured())
		{
			(void)fprintf(stderr,
				"TLS: cannot load %s / %s: %s\n",
				TLS_CERT_FILE, TLS_KEY_FILE, err);
			return -1;
		}
		sendto_flag(SCH_ERROR, "TLS: cannot load %s / %s: %s%s",
			TLS_CERT_FILE, TLS_KEY_FILE, err,
			tls_ctx ? " (keeping previous certificate)" : "");
		return startup ? 0 : -1;
	}
	if (tls_ctx)
		SSL_CTX_free(tls_ctx);	/* live connections hold a reference */
	tls_ctx = ctx;
	if (!startup)
		sendto_flag(SCH_NOTICE, "TLS: certificate reloaded from %s",
			TLS_CERT_FILE);
	return 0;
}

/* start TLS on a freshly accepted socket */
int	tls_accept(aClient *cptr, int fd)
{
	if (!tls_ctx)
	{
		sendto_flag(SCH_ERROR, "TLS: no certificate loaded, "
			"refusing connection from %s", cptr->sockhost);
		return -1;
	}
	if (!(cptr->ssl = SSL_new(tls_ctx)))
	{
		sendto_flag(SCH_ERROR, "TLS: SSL_new: %s", tls_lasterr());
		return -1;
	}
	if (SSL_set_fd(cptr->ssl, fd) != 1)
	{
		sendto_flag(SCH_ERROR, "TLS: SSL_set_fd: %s", tls_lasterr());
		SSL_free(cptr->ssl);
		cptr->ssl = NULL;
		return -1;
	}
	SSL_set_accept_state(cptr->ssl);
	cptr->flags |= FLAGS_TLSHS;
	return 0;
}

static	void	tls_set_certfp(aClient *cptr)
{
	X509	*cert;
	unsigned char	md[EVP_MAX_MD_SIZE];
	unsigned int	n = 0, i;
	char	*p;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	cert = SSL_get1_peer_certificate(cptr->ssl);
#else
	cert = SSL_get_peer_certificate(cptr->ssl);
#endif
	if (!cert)
		return;
	if (X509_digest(cert, EVP_sha256(), md, &n) == 1 && n > 0)
	{
		cptr->certfp = (char *)MyMalloc(2 * n + 1);
		for (p = cptr->certfp, i = 0; i < n; i++, p += 2)
			sprintf(p, "%02x", md[i]);
	}
	X509_free(cert);
}

/*
 * Drive the handshake.
 * Returns 1 when finished, 0 when it needs more I/O, -1 on failure.
 */
static	int	tls_handshake(aClient *cptr)
{
	int	r, e;

	ERR_clear_error();
	r = SSL_do_handshake(cptr->ssl);
	if (r == 1)
	{
		cptr->flags &= ~(FLAGS_TLSHS|FLAGS_TLSWANTW);
		tls_set_certfp(cptr);
		Debug((DEBUG_DEBUG, "TLS: %s %s %s certfp %s",
			cptr->sockhost, SSL_get_version(cptr->ssl),
			SSL_get_cipher_name(cptr->ssl),
			cptr->certfp ? cptr->certfp : "-"));
		return 1;
	}
	e = SSL_get_error(cptr->ssl, r);
	if (e == SSL_ERROR_WANT_READ)
	{
		cptr->flags &= ~FLAGS_TLSWANTW;
		return 0;
	}
	if (e == SSL_ERROR_WANT_WRITE)
	{
		cptr->flags |= FLAGS_TLSWANTW;
		return 0;
	}
	if (e == SSL_ERROR_SYSCALL && ERR_peek_error() == 0)
		sprintf(tls_errbuf, "%s", r == 0 ? "connection closed" :
			strerror(errno));
	else
		(void)tls_lasterr();
	return -1;
}

/*
 * read_packet() replacement for recv().
 * Returns >0 bytes, 0 on EOF, -1 with errno EAGAIN when nothing could be
 * read yet, -2 on a TLS failure (reason via tls_error()).
 */
int	tls_read(aClient *cptr, char *buf, int len)
{
	int	r, e;

	if (cptr->flags & FLAGS_TLSHS)
	{
		r = tls_handshake(cptr);
		if (r < 0)
			return -2;
		if (r == 0)
		{
			errno = EAGAIN;
			return -1;
		}
		/* handshake done: application data may already be waiting */
	}
	ERR_clear_error();
	r = SSL_read(cptr->ssl, buf, len);
	if (r > 0)
		return r;
	e = SSL_get_error(cptr->ssl, r);
	switch (e)
	{
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		return -1;
	case SSL_ERROR_WANT_WRITE:
		cptr->flags |= FLAGS_TLSWANTW;
		errno = EAGAIN;
		return -1;
	case SSL_ERROR_ZERO_RETURN:
		return 0;	/* close_notify */
	case SSL_ERROR_SYSCALL:
		if (ERR_peek_error() == 0)
		{
			if (r == 0)
				return 0;	/* EOF without close_notify */
			sprintf(tls_errbuf, "%s", strerror(errno));
			return -2;
		}
		/* FALLTHROUGH */
	default:
		(void)tls_lasterr();
		return -2;
	}
}

/*
 * deliver_it() replacement for send().  Same convention as deliver_it():
 * >= 0 bytes written (0 = try again later), < 0 fatal (-errno).
 */
int	tls_write(aClient *cptr, char *buf, int len)
{
	int	r, e;

	if (cptr->flags & FLAGS_TLSHS)
	{
		/* nothing is sent before the handshake is complete */
		if (tls_handshake(cptr) < 0)
			return -EIO;
		return 0;
	}
	ERR_clear_error();
	r = SSL_write(cptr->ssl, buf, len);
	if (r > 0)
	{
		cptr->flags &= ~(FLAGS_BLOCKED|FLAGS_TLSWANTW);
		return r;
	}
	e = SSL_get_error(cptr->ssl, r);
	if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ)
	{
		cptr->flags |= FLAGS_BLOCKED;
		return 0;
	}
	if (e == SSL_ERROR_SYSCALL && ERR_peek_error() == 0)
		return errno ? -errno : -EPIPE;
	(void)tls_lasterr();
	return -EIO;
}

/*
 * Called when the socket is writable and the TLS layer asked for it
 * (handshake data that did not fit).  Returns -1 on failure.
 */
int	tls_writable(aClient *cptr)
{
	if (!cptr->ssl || !(cptr->flags & FLAGS_TLSWANTW))
		return 0;
	cptr->flags &= ~FLAGS_TLSWANTW;
	if (cptr->flags & FLAGS_TLSHS)
		return tls_handshake(cptr) < 0 ? -1 : 0;
	return 0;
}

/* should the main loop arm a write event for this client? */
int	tls_want_write(aClient *cptr)
{
	if (!cptr->ssl)
		return -1;	/* not a TLS client: decide as usual */
	if (cptr->flags & FLAGS_TLSWANTW)
		return 1;
	if (cptr->flags & FLAGS_TLSHS)
		return 0;	/* waiting for the client: don't spin */
	return -1;
}

char	*tls_error(void)
{
	return tls_errbuf;
}

/* close the TLS session before the socket is closed */
void	tls_close(aClient *cptr)
{
	if (!cptr->ssl)
		return;
	if (!(cptr->flags & FLAGS_TLSHS))
	{
		ERR_clear_error();
		(void)SSL_shutdown(cptr->ssl);	/* send close_notify */
	}
	SSL_free(cptr->ssl);
	ERR_clear_error();
	cptr->ssl = NULL;
	cptr->flags &= ~(FLAGS_TLSHS|FLAGS_TLSWANTW);
}

/* release everything (from free_client()) */
void	tls_free(aClient *cptr)
{
	tls_close(cptr);
	if (cptr->certfp)
	{
		MyFree(cptr->certfp);
		cptr->certfp = NULL;
	}
}

char	*tls_cipher(aClient *cptr)
{
	static	char	cbuf[128];

	if (!cptr->ssl || (cptr->flags & FLAGS_TLSHS))
		return NULL;
	sprintf(cbuf, "%.20s %.100s", SSL_get_version(cptr->ssl),
		SSL_get_cipher_name(cptr->ssl));
	return cbuf;
}

#endif /* USE_SSL */

/*
 * Compare a client's fingerprint with a configured one.  The configured
 * value may use upper case and ':' separators; it ends at the first ','
 * or at the end of the string.
 */
int	certfp_match(char *have, char *conf)
{
	if (BadPtr(have) || BadPtr(conf))
		return 0;
	while (*conf && *conf != ',')
	{
		if (*conf == ':')
		{
			conf++;
			continue;
		}
		if (!*have || tolower((unsigned char)*conf) != *have)
			return 0;
		conf++;
		have++;
	}
	return *have == '\0';
}

/*
 * Check a password field from an I-line or O-line.
 *	certfp=<sha256>			client certificate must match
 *	certfp=<sha256>,<password>	certificate and password must match
 * Returns 1 if the line uses certfp= (and sets *rest to the password part
 * or NULL, *ok to whether the certificate matched), 0 otherwise.
 */
int	conf_certfp(aClient *cptr, char *confpass, char **rest, int *ok)
{
	char	*comma;

	if (BadPtr(confpass) || strncasecmp(confpass, "certfp=", 7))
		return 0;
	comma = index(confpass + 7, ',');
	*rest = comma ? comma + 1 : NULL;
#ifdef USE_SSL
	*ok = MyConnect(cptr) && certfp_match(cptr->certfp, confpass + 7);
#else
	*ok = 0;
#endif
	return 1;
}

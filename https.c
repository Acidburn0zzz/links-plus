/* https.c
 * HTTPS protocol client implementation
 * (c) 2002 Mikulas Patocka
 * This file is a part of the Links program, released under GPL.

 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include "links.h"

#ifndef PATH_MAX
#define PATH_MAX 255
#endif

#ifdef HAVE_SSL

#define VERIFY_DEPTH	10

static SSL_CTX *context = NULL;

static int verify_cert(int code, X509_STORE_CTX *context)
{
	int error, depth;

	error = X509_STORE_CTX_get_error(context);
	depth = X509_STORE_CTX_get_error_depth(context);

	if (depth > VERIFY_DEPTH) {
		error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
		code = 0;
	}

	if (!code) {
		/* Judge self signed certificates as acceptable. */
		if (error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
				error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
			code = 1;
		} else {
			fprintf(stderr, "Verification failure: %s\n",
						X509_verify_cert_error_string(error));
			if (depth > VERIFY_DEPTH) {
				fprintf(stderr, "Excessive depth %d, set depth %d.\n",
							depth, VERIFY_DEPTH);
			}
		}
	}

	return code;
} /* verify_cert */

SSL *getSSL(void)
{
	if (!context) {
		const SSL_METHOD *m;
		unsigned char f_randfile[PATH_MAX];
		unsigned char *os_pool;
		unsigned os_pool_size;

		const unsigned char *f = (const unsigned char *)RAND_file_name(cast_char f_randfile, sizeof(f_randfile));
		if (RAND_load_file(cast_const_char f_randfile, -1))
			RAND_write_file(cast_const_char f_randfile);

		os_seed_random(&os_pool, &os_pool_size);
		if (os_pool_size) RAND_add(os_pool, os_pool_size, os_pool_size);
		mem_free(os_pool);

/* needed for systems without /dev/random, but obviously kills security. */
		/*{
			static unsigned char pool[32768];
			int i;
			int rs;
			struct timeval tv;
			EINTRLOOP(rs, gettimeofday(&tv, NULL));
			for (i = 0; i < (int)sizeof pool; i++) pool[i] = random() ^ tv.tv_sec ^ tv.tv_usec;
			RAND_add(pool, sizeof pool, sizeof pool);
		}*/

		SSLeay_add_ssl_algorithms();
		m = SSLv23_client_method();
		if (!m) return NULL;
		context = SSL_CTX_new((void *)m);
		if (!context) return NULL;
		SSL_CTX_set_options(context, SSL_OP_NO_SSLv2 | SSL_OP_ALL);
		SSL_CTX_set_mode(context, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_default_verify_paths(context);
		SSL_CTX_set_verify(context, SSL_VERIFY_PEER, verify_cert);

	}
	return (SSL_new(context));
}
void ssl_finish(void)
{
	if (context) SSL_CTX_free(context);
}

void https_func(struct connection *c)
{
	c->ssl = DUMMY;
	http_func(c);
}

#else

void https_func(struct connection *c)
{
	setcstate(c, S_NO_SSL);
	abort_connection(c);
}

#endif

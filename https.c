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

//static SSL_CTX *context = NULL;
//
//SSL *getSSL(void)
//{
//	if (!context) {
//		const SSL_METHOD *m;
//		unsigned char f_randfile[PATH_MAX];
//		unsigned char *os_pool;
//		unsigned os_pool_size;
//
//#if defined(HAVE_RAND_EGD) && defined(HAVE_RAND_FILE_NAME) && defined(HAVE_RAND_LOAD_FILE) && defined(HAVE_RAND_WRITE_FILE)
//		const unsigned char *f = (const unsigned char *)RAND_file_name(cast_char f_randfile, sizeof(f_randfile));
//		if (f && RAND_egd(cast_const_char f) < 0) {
//			/* Not an EGD, so read and write to it */
//			if (RAND_load_file(cast_const_char f_randfile, -1))
//				RAND_write_file(cast_const_char f_randfile);
//		}
//#endif
//
//#if defined(HAVE_RAND_ADD)
//		os_seed_random(&os_pool, &os_pool_size);
//		if (os_pool_size) RAND_add(os_pool, os_pool_size, os_pool_size);
//		mem_free(os_pool);
//#endif
//
//		SSLeay_add_ssl_algorithms();
//		m = SSLv23_client_method();
//		if (!m) return NULL;
//		context = SSL_CTX_new((void *)m);
//		if (!context) return NULL;
//		SSL_CTX_set_options(context, SSL_OP_ALL);
//		SSL_CTX_set_default_verify_paths(context);
//
//	}
//	return (SSL_new(context));
//}
//void ssl_finish(void)
//{
//	if (context) SSL_CTX_free(context);
//}

void https_func(struct connection *c)
{
	c->tls = DUMMY;
	http_func(c);
}

#else

void https_func(struct connection *c)
{
	setcstate(c, S_NO_SSL);
	abort_connection(c);
}

#endif

/*
 * "$Id$"
 *
 * TLS support code for CUPS using OpenSSL.
 *
 * Copyright 2007-2012 by Apple Inc.
 * Copyright 1997-2007 by Easy Software Products, all rights reserved.
 *
 * These coded instructions, statements, and computer programs are the
 * property of Apple Inc. and are protected by Federal copyright
 * law.  Distribution and use rights are outlined in the file "LICENSE.txt"
 * which should have been included with this file.  If this file is
 * file is missing or damaged, see the license at "http://www.cups.org/".
 *
 * This file is subject to the Apple OS-Developed Software exception.
 */


/*
 * Local functions...
 */

static int		make_certificate(cupsd_client_t *con);
/*
 * BIO methods for OpenSSL...
 */

static int		http_bio_write(BIO *h, const char *buf, int num);
static int		http_bio_read(BIO *h, char *buf, int size);
static int		http_bio_puts(BIO *h, const char *str);
static long		http_bio_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int		http_bio_new(BIO *h);
static int		http_bio_free(BIO *data);

static BIO_METHOD	http_bio_methods =
			{
			  BIO_TYPE_SOCKET,
			  "http",
			  http_bio_write,
			  http_bio_read,
			  http_bio_puts,
			  NULL, /* http_bio_gets, */
			  http_bio_ctrl,
			  http_bio_new,
			  http_bio_free,
			  NULL,
			};




/*
 * 'http_tls_initialize()' - Initialize the TLS stack.
 */

static void
http_tls_initialize(void)
{
 /*
  * Initialize OpenSSL...
  */

  SSL_load_error_strings();
  SSL_library_init();

 /*
  * Using the current time is a dubious random seed, but on some systems
  * it is the best we can do (on others, this seed isn't even used...)
  */

  CUPS_SRAND(time(NULL));

  for (i = 0; i < sizeof(data); i ++)
    data[i] = CUPS_RAND();

  RAND_seed(data, sizeof(data));
}


/*
 * 'http_tls_read()' - Read from a SSL/TLS connection.
 */

static int				/* O - Bytes read */
http_tls_read(http_t *http,		/* I - Connection to server */
	      char   *buf,		/* I - Buffer to store data */
	      int    len)		/* I - Length of buffer */
{  return (SSL_read((SSL *)(http->tls), buf, len));
}


#ifdef HAVE_SSL
/*
 * 'http_setup_ssl()' - Set up SSL/TLS support on a connection.
 */

static int				/* O - 0 on success, -1 on failure */
http_setup_ssl(http_t *http)		/* I - Connection to server */
{
  char			hostname[256],	/* Hostname */
			*hostptr;	/* Pointer into hostname */
  SSL_CTX		*context;	/* Context for encryption */
  BIO			*bio;		/* BIO data */
  const char		*message = NULL;/* Error message */


  DEBUG_printf(("7http_setup_ssl(http=%p)", http));

 /*
  * Get the hostname to use for SSL...
  */

  if (httpAddrLocalhost(http->hostaddr))
  {
    strlcpy(hostname, "localhost", sizeof(hostname));
  }
  else
  {
   /*
    * Otherwise make sure the hostname we have does not end in a trailing dot.
    */

    strlcpy(hostname, http->hostname, sizeof(hostname));
    if ((hostptr = hostname + strlen(hostname) - 1) >= hostname &&
        *hostptr == '.')
      *hostptr = '\0';
  }

  context = SSL_CTX_new(SSLv23_client_method());

  SSL_CTX_set_options(context, SSL_OP_NO_SSLv2); /* Only use SSLv3 or TLS */

  bio = BIO_new(_httpBIOMethods());
  BIO_ctrl(bio, BIO_C_SET_FILE_PTR, 0, (char *)http);

  http->tls = SSL_new(context);
  SSL_set_bio(http->tls, bio, bio);

#   ifdef HAVE_SSL_SET_TLSEXT_HOST_NAME
  SSL_set_tlsext_host_name(http->tls, hostname);
#   endif /* HAVE_SSL_SET_TLSEXT_HOST_NAME */

  if (SSL_connect(http->tls) != 1)
  {
    unsigned long	error;	/* Error code */

    while ((error = ERR_get_error()) != 0)
    {
      message = ERR_error_string(error, NULL);
      DEBUG_printf(("8http_setup_ssl: %s", message));
    }

    SSL_CTX_free(context);
    SSL_free(http->tls);
    http->tls = NULL;
    http->error  = errno;
    http->status = HTTP_STATUS_ERROR;

    if (!message)
      message = _("Unable to establish a secure connection to host.");

    _cupsSetError(IPP_STATUS_ERROR_CUPS_PKI, message, 1);

    return (-1);
  }

  return (0);
}


/*
 * 'http_shutdown_ssl()' - Shut down SSL/TLS on a connection.
 */

static void
http_shutdown_ssl(http_t *http)		/* I - Connection to server */
{  SSL_CTX	*context;		/* Context for encryption */

  context = SSL_get_SSL_CTX(http->tls);

  SSL_shutdown(http->tls);
  SSL_CTX_free(context);
  SSL_free(http->tls);


  http->tls             = NULL;
  http->tls_credentials = NULL;
}

/*
 * 'http_write_ssl()' - Write to a SSL/TLS connection.
 */

static int				/* O - Bytes written */
http_write_ssl(http_t     *http,	/* I - Connection to server */
	       const char *buf,		/* I - Buffer holding data */
	       int        len)		/* I - Length of buffer */
{
  ssize_t	result;			/* Return value */


  DEBUG_printf(("2http_write_ssl(http=%p, buf=%p, len=%d)", http, buf, len));

  result = SSL_write((SSL *)(http->tls), buf, len);


  DEBUG_printf(("3http_write_ssl: Returning %d.", (int)result));

  return ((int)result);
}


/*
 * 'http_tls_pending()' - Return the number of pending TLS-encrypted bytes.
 */

static size_t
http_tls_pending(http_t *http)		/* I - HTTP connection */
{
  if (http->tls && usessl)
  {
    if (SSL_pending(http->tls))
    {
      DEBUG_puts("5_httpWait: Return 1 since there is pending SSL data.");
      return (1);
    }
}

/*
 * 'http_bio_ctrl()' - Control the HTTP connection.
 */

static long				/* O - Result/data */
http_bio_ctrl(BIO  *h,			/* I - BIO data */
              int  cmd,			/* I - Control command */
	      long arg1,		/* I - First argument */
	      void *arg2)		/* I - Second argument */
{
  switch (cmd)
  {
    default :
        return (0);

    case BIO_CTRL_RESET :
        h->ptr = NULL;
	return (0);

    case BIO_C_SET_FILE_PTR :
        h->ptr  = arg2;
	h->init = 1;
	return (1);

    case BIO_C_GET_FILE_PTR :
        if (arg2)
	{
	  *((void **)arg2) = h->ptr;
	  return (1);
	}
	else
	  return (0);

    case BIO_CTRL_DUP :
    case BIO_CTRL_FLUSH :
        return (1);
  }
}


/*
 * 'http_bio_free()' - Free OpenSSL data.
 */

static int				/* O - 1 on success, 0 on failure */
http_bio_free(BIO *h)			/* I - BIO data */
{
  if (!h)
    return (0);

  if (h->shutdown)
  {
    h->init  = 0;
    h->flags = 0;
  }

  return (1);
}


/*
 * 'http_bio_new()' - Initialize an OpenSSL BIO structure.
 */

static int				/* O - 1 on success, 0 on failure */
http_bio_new(BIO *h)			/* I - BIO data */
{
  if (!h)
    return (0);

  h->init  = 0;
  h->num   = 0;
  h->ptr   = NULL;
  h->flags = 0;

  return (1);
}


/*
 * 'http_bio_puts()' - Send a string for OpenSSL.
 */

static int				/* O - Bytes written */
http_bio_puts(BIO        *h,		/* I - BIO data */
              const char *str)		/* I - String to write */
{
  return (send(((http_t *)h->ptr)->fd, str, strlen(str), 0));
}


/*
 * 'http_bio_read()' - Read data for OpenSSL.
 */

static int				/* O - Bytes read */
http_bio_read(BIO  *h,			/* I - BIO data */
              char *buf,		/* I - Buffer */
	      int  size)		/* I - Number of bytes to read */
{
  http_t	*http;			/* HTTP connection */


  http = (http_t *)h->ptr;

  if (!http->blocking)
  {
   /*
    * Make sure we have data before we read...
    */

    while (!_httpWait(http, http->wait_value, 0))
    {
      if (http->timeout_cb && (*http->timeout_cb)(http, http->timeout_data))
	continue;
      http->error = ETIMEDOUT;

      return (-1);
    }
  }

  return (recv(http->fd, buf, size, 0));
}


/*
 * 'http_bio_write()' - Write data for OpenSSL.
 */

static int				/* O - Bytes written */
http_bio_write(BIO        *h,		/* I - BIO data */
               const char *buf,		/* I - Buffer to write */
	       int        num)		/* I - Number of bytes to write */
{
  return (send(((http_t *)h->ptr)->fd, buf, num, 0));
}

/*
 * 'cupsdEndTLS()' - Shutdown a secure session with the client.
 */

int					/* O - 1 on success, 0 on error */
cupsdEndTLS(cupsd_client_t *con)	/* I - Client connection */
{
  SSL_CTX	*context;		/* Context for encryption */
  unsigned long	error;			/* Error code */
  int		status;			/* Return status */


  context = SSL_get_SSL_CTX(con->http.tls);

  switch (SSL_shutdown(con->http.tls))
  {
    case 1 :
	cupsdLogMessage(CUPSD_LOG_DEBUG,
			"SSL shutdown successful!");
	status = 1;
	break;

    case -1 :
	cupsdLogMessage(CUPSD_LOG_ERROR,
			"Fatal error during SSL shutdown!");

    default :
	while ((error = ERR_get_error()) != 0)
	  cupsdLogMessage(CUPSD_LOG_ERROR, "SSL shutdown failed: %s",
			  ERR_error_string(error, NULL));
	status = 0;
	break;
  }

  SSL_CTX_free(context);
  SSL_free(con->http.tls);
  con->http.tls = NULL;

  return (status);
}


/*
 * 'cupsdStartTLS()' - Start a secure session with the client.
 */

int					/* O - 1 on success, 0 on error */
cupsdStartTLS(cupsd_client_t *con)	/* I - Client connection */
{
  SSL_CTX	*context;		/* Context for encryption */
  BIO		*bio;			/* BIO data */
  unsigned long	error;			/* Error code */


  cupsdLogMessage(CUPSD_LOG_DEBUG, "[Client %d] Encrypting connection.",
                  con->http.fd);

 /*
  * Verify that we have a certificate...
  */

  if (access(ServerKey, 0) || access(ServerCertificate, 0))
  {
   /*
    * Nope, make a self-signed certificate...
    */

    if (!make_certificate(con))
      return (0);
  }

 /*
  * Create the SSL context and accept the connection...
  */

  context = SSL_CTX_new(SSLv23_server_method());

  SSL_CTX_set_options(context, SSL_OP_NO_SSLv2); /* Only use SSLv3 or TLS */
  if (SSLOptions & CUPSD_SSL_NOEMPTY)
    SSL_CTX_set_options(context, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
  SSL_CTX_use_PrivateKey_file(context, ServerKey, SSL_FILETYPE_PEM);
  SSL_CTX_use_certificate_chain_file(context, ServerCertificate);

  bio = BIO_new(_httpBIOMethods());
  BIO_ctrl(bio, BIO_C_SET_FILE_PTR, 0, (char *)HTTP(con));

  con->http.tls = SSL_new(context);
  SSL_set_bio(con->http.tls, bio, bio);

  if (SSL_accept(con->http.tls) != 1)
  {
    cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to encrypt connection from %s.",
                    con->http.hostname);

    while ((error = ERR_get_error()) != 0)
      cupsdLogMessage(CUPSD_LOG_ERROR, "%s", ERR_error_string(error, NULL));

    SSL_CTX_free(context);
    SSL_free(con->http.tls);
    con->http.tls = NULL;
    return (0);
  }

  cupsdLogMessage(CUPSD_LOG_DEBUG, "Connection from %s now encrypted.",
                  con->http.hostname);

  return (1);
}


/*
 * 'make_certificate()' - Make a self-signed SSL/TLS certificate.
 */

static int				/* O - 1 on success, 0 on failure */
make_certificate(cupsd_client_t *con)	/* I - Client connection */
{
#ifdef HAVE_WAITPID
  int		pid,			/* Process ID of command */
		status;			/* Status of command */
  char		command[1024],		/* Command */
		*argv[12],		/* Command-line arguments */
		*envp[MAX_ENV + 1],	/* Environment variables */
		infofile[1024],		/* Type-in information for cert */
		seedfile[1024];		/* Random number seed file */
  int		envc,			/* Number of environment variables */
		bytes;			/* Bytes written */
  cups_file_t	*fp;			/* Seed/info file */
  int		infofd;			/* Info file descriptor */


 /*
  * Run the "openssl" command to seed the random number generator and
  * generate a self-signed certificate that is good for 10 years:
  *
  *     openssl rand -rand seedfile 1
  *
  *     openssl req -new -x509 -keyout ServerKey \
  *             -out ServerCertificate -days 3650 -nodes
  *
  * The seeding step is crucial in ensuring that the openssl command
  * does not block on systems without sufficient entropy...
  */

  if (!cupsFileFind("openssl", getenv("PATH"), 1, command, sizeof(command)))
  {
    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "No SSL certificate and openssl command not found!");
    return (0);
  }

  if (access("/dev/urandom", 0))
  {
   /*
    * If the system doesn't provide /dev/urandom, then any random source
    * will probably be blocking-style, so generate some random data to
    * use as a seed for the certificate.  Note that we have already
    * seeded the random number generator in cupsdInitCerts()...
    */

    cupsdLogMessage(CUPSD_LOG_INFO,
                    "Seeding the random number generator...");

   /*
    * Write the seed file...
    */

    if ((fp = cupsTempFile2(seedfile, sizeof(seedfile))) == NULL)
    {
      cupsdLogMessage(CUPSD_LOG_ERROR, "Unable to create seed file %s - %s",
                      seedfile, strerror(errno));
      return (0);
    }

    for (bytes = 0; bytes < 262144; bytes ++)
      cupsFilePutChar(fp, CUPS_RAND());

    cupsFileClose(fp);

   /*
    * Run the openssl command to seed its random number generator...
    */

    argv[0] = "openssl";
    argv[1] = "rand";
    argv[2] = "-rand";
    argv[3] = seedfile;
    argv[4] = "1";
    argv[5] = NULL;

    envc = cupsdLoadEnv(envp, MAX_ENV);
    envp[envc] = NULL;

    if (!cupsdStartProcess(command, argv, envp, -1, -1, -1, -1, -1, 1, NULL,
                           NULL, &pid))
    {
      unlink(seedfile);
      return (0);
    }

    while (waitpid(pid, &status, 0) < 0)
      if (errno != EINTR)
      {
	status = 1;
	break;
      }

    cupsdFinishProcess(pid, command, sizeof(command), NULL);

   /*
    * Remove the seed file, as it is no longer needed...
    */

    unlink(seedfile);

    if (status)
    {
      if (WIFEXITED(status))
	cupsdLogMessage(CUPSD_LOG_ERROR,
                	"Unable to seed random number generator - "
			"the openssl command stopped with status %d!",
	        	WEXITSTATUS(status));
      else
	cupsdLogMessage(CUPSD_LOG_ERROR,
                	"Unable to seed random number generator - "
			"the openssl command crashed on signal %d!",
	        	WTERMSIG(status));

      return (0);
    }
  }

 /*
  * Create a file with the certificate information fields...
  *
  * Note: This assumes that the default questions are asked by the openssl
  * command...
  */

  if ((fp = cupsTempFile2(infofile, sizeof(infofile))) == NULL)
  {
    cupsdLogMessage(CUPSD_LOG_ERROR,
                    "Unable to create certificate information file %s - %s",
                    infofile, strerror(errno));
    return (0);
  }

  cupsFilePrintf(fp, ".\n.\n.\n%s\n.\n%s\n%s\n",
                 ServerName, ServerName, ServerAdmin);
  cupsFileClose(fp);

  cupsdLogMessage(CUPSD_LOG_INFO,
                  "Generating SSL server key and certificate...");

  argv[0]  = "openssl";
  argv[1]  = "req";
  argv[2]  = "-new";
  argv[3]  = "-x509";
  argv[4]  = "-keyout";
  argv[5]  = ServerKey;
  argv[6]  = "-out";
  argv[7]  = ServerCertificate;
  argv[8]  = "-days";
  argv[9]  = "3650";
  argv[10] = "-nodes";
  argv[11] = NULL;

  cupsdLoadEnv(envp, MAX_ENV);

  infofd = open(infofile, O_RDONLY);

  if (!cupsdStartProcess(command, argv, envp, infofd, -1, -1, -1, -1, 1, NULL,
                         NULL, &pid))
  {
    close(infofd);
    unlink(infofile);
    return (0);
  }

  close(infofd);
  unlink(infofile);

  while (waitpid(pid, &status, 0) < 0)
    if (errno != EINTR)
    {
      status = 1;
      break;
    }

  cupsdFinishProcess(pid, command, sizeof(command), NULL);

  if (status)
  {
    if (WIFEXITED(status))
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "Unable to create SSL server key and certificate - "
		      "the openssl command stopped with status %d!",
	              WEXITSTATUS(status));
    else
      cupsdLogMessage(CUPSD_LOG_ERROR,
                      "Unable to create SSL server key and certificate - "
		      "the openssl command crashed on signal %d!",
	              WTERMSIG(status));
  }
  else
  {
    cupsdLogMessage(CUPSD_LOG_INFO, "Created SSL server key file \"%s\"...",
		    ServerKey);
    cupsdLogMessage(CUPSD_LOG_INFO,
                    "Created SSL server certificate file \"%s\"...",
		    ServerCertificate);
  }

  return (!status);

#else
  return (0);
#endif /* HAVE_WAITPID */
}


/*
 * End of "$Id$".
 */

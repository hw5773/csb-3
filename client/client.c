#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>
#include <sys/time.h>
#include <pthread.h>
#include <getopt.h>

#include "rsa.h"
#include "../include/debug.h"
#include "../include/defines.h"
#include "../include/setting.h"
#include "../include/conn.h"
#include "../include/http.h"
#include "../include/net.h"
#include "../include/err.h"

int usage(const char *pname)
{
  emsg(">> usage: %s [-h <domain>] [--host <domain>] [-p <portnum>] [--port <portnum>] [--sk <private key file>] [--pk <public key file>]", pname);
  emsg(">> example: %s -h www.alice.com -p 5555 --sk ../key/client_priv.pem --pk ../key/client_pub.pem", pname);
  exit(0);
}

// Client Prototype Implementation
int main(int argc, char *argv[])
{   
  const char *domain, *skname, *pkname, *pname;
	int i, port, server;
  struct keypair *kst, *peer;
  unsigned char buf[BUF_SIZE] = {0, };
  unsigned char my_pk[BUF_SIZE] = {0, };
  unsigned char peer_pk[BUF_SIZE] = {0, };
  unsigned char plain[BUF_SIZE] = {0, };
  unsigned char ciph[BUF_SIZE] = {0, };
  unsigned char msg[NUM_OF_PROBLEMS][BUF_SIZE];
  unsigned char sign[NUM_OF_PROBLEMS][BUF_SIZE];
  unsigned char *sptr;
  int mlen[NUM_OF_PROBLEMS];
  int slen[NUM_OF_PROBLEMS];
  unsigned char verified;
  const char *start = "Start";
  int ret, len, clen, rlen, plen, klen, c, err, answer;

  pname = argv[0];
  domain = NULL;
  port = -1;
  skname = NULL;
  pkname = NULL;
  err = 0;
  i = 0;
  answer = -1;

  SSL_library_init();
  OpenSSL_add_all_algorithms();

  for (i=0; i<NUM_OF_PROBLEMS; i++)
  {
    memset(msg[i], 0x0, BUF_SIZE);
    memset(sign[i], 0x0, BUF_SIZE);
  }

  /* Get command line arguments */
  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"host", required_argument, 0, 'h'},
      {"port", required_argument, 0, 'p'},
      {"sk", required_argument, 0, 'a'},
      {"pk", required_argument, 0, 'b'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "a:b:h:p:0", long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'h':
        domain = optarg;
        imsg("Domain: %s", domain);
        break;
      case 'p':
        port = atoi(optarg);
        imsg("Port: %d", port);
        break;
      case 'a':
        if (access(optarg, F_OK) != -1)
        {
          skname = optarg;
          imsg("Private Key File Path: %s", skname);
        }
        else
        {
          skname = NULL;
          emsg("Wrong private key file: %s", optarg);
        }
        break;
      case 'b':
        if (access(optarg, F_OK) != -1)
        {
          pkname = optarg;
          imsg("Public Key File Path: %s", pkname);
        }
        else
        {
          pkname = NULL;
          emsg("Wrong public key file: %s", optarg);
        }
        break;
      default:
        usage(pname);
    }
  }

  /* Handle errors */
  if (!domain)
  {
    err |= ERR_DOMAIN_NAME;
  }
  
  if (port < 0)
  {
    err |= ERR_PORT_NUMBER;
  }

  if (!skname)
  {
    err |= ERR_PRIV_KEY_FILE;
  }

  if (!pkname)
  {
    err |= ERR_PUB_KEY_FILE;
  }

  if (err)
  {
    emsg("Error in arguments");
    if (err & ERR_DOMAIN_NAME)
      emsg("Please insert the domain name (or IP address) of the server with the '-h' or '--host' flag.");

    if (err & ERR_PORT_NUMBER)
      emsg("Please insert the port number of the server with the '-p' or '--port' flag.");

    if (err & ERR_PRIV_KEY_FILE)
      emsg("Please insert the RSA private key for the client with the '--sk' flag.");

    if (err & ERR_PUB_KEY_FILE)
      emsg("Please insert the RSA public key for the client with the '--pk' flag.");

    usage(pname);
  }

  /* TODO: Initialize the RSA keypair */
  kst = init_rsa_keypair(skname, pkname);
  if (!kst)
  {
    emsg("Initialize the RSA keypair failed");
    abort();
  }

  /* Set the TCP connection with the server */
	server = open_connection(domain, port);
  if (server <= 2)
  {
    emsg("Open TCP connection failed");
    abort();
  }

  /* Send the Start message to Server */
  ret = send_message(server, start, strlen(start));
  if (ret == FAILURE)
  {
    emsg("Send the Start message failed");
    abort();
  }

  /* Make the RSA public key to bytes */
  ret = make_rsa_pubkey_to_bytes(kst, my_pk, &len);
  if (ret == FAILURE)
  {
    emsg("Translate the RSA public key into the bytes");
    abort();
  }

  /* Send the RSA public key bytes to Server */
  ret = send_message(server, my_pk, len);
  if (ret == FAILURE)
  {
    emsg("Send the key bytes failed");
    abort();
  }
  iprint("Client's public key", my_pk, 0, len, ONE_LINE);

  /* Receive the Server's RSA public key */
  ret = receive_message(server, buf, BUF_SIZE);
  if (ret == FAILURE)
  {
    emsg("Receive the Server's public key failed");
    abort();
  }
  rlen = ret;

  /* Initialize the RSA keypair */
  peer = init_rsa_keypair(NULL, NULL);
  if (!peer)
  {
    emsg("Initialize the RSA keypair failed");
    abort();
  }

  /* Make the bytes to the Server's public key */
  ret = make_bytes_to_rsa_pubkey(peer, buf, rlen);
  if (ret == FAILURE)
  {
    emsg("Translate the bytes to the RSA public key");
    abort();
  }

  for (i=0; i<NUM_OF_PROBLEMS; i++)
  {
    /* Receive the challenge message from Server */
    ret = receive_message(server, msg[i], BUF_SIZE);
    if (ret == FAILURE)
    {
      emsg("Receive the challenge message failed");
      abort();
    }
    mlen[i] = ret;
  
    /* Receive the challenge message from Server */
    ret = receive_message(server, sign[i], BUF_SIZE);
    if (ret == FAILURE)
    {
      emsg("Receive the challenge message failed");
      abort();
    }
    sptr = sign[i];
    slen[i] = ret;

    /* TODO: Verify the challenge message (signed with Server's private key) */
    ret = rsa_operation(peer, sign[i], slen[i], msg[i], &(mlen[i]), RSA_VERIFY);
    if (ret == FAILURE)
    {
      emsg("%s is not the answer", msg[i]);
    }
    else
    {
      imsg("%s is the answer", msg[i]);
      answer = i;
    }
    imsg("Challenge (%d bytes): %s", mlen[i], msg[i]);
    iprint("Received signature", sptr, 0, slen[i], ONE_LINE);
  }

  /* Constraint */
  if (answer < 0)
  {
    emsg("You did not find the right signature");
    emsg("Please check your signature/verification functions");
    assert(answer >= 0);
  }

  /* TODO: Sign the challenge message with Client's private key */
  ret = rsa_operation(kst, msg[answer], mlen[answer], buf, &len, RSA_SIGN);
  if (ret == FAILURE)
  {
    emsg("Encrypt the challenge message failed");
    abort();
  }

  /* Send the signature to Server */
  ret = send_message(server, buf, len);
  if (ret == FAILURE)
  {
    emsg("Send the signature failed");
    abort();
  }
  iprint("Sent message", buf, 0, len, ONE_LINE);

  /* Receive the result from Server */
  ret = receive_message(server, buf, BUF_SIZE);
  if (ret == FAILURE)
  {
    emsg("Receive the result failed");
    abort();
  }
  rlen = ret;
  verified = buf[0];
  imsg("Answer: %s / Received message: %d", msg[answer], verified);

  if (verified)
  {
    imsg("Success!");
  }
  else
  {
    imsg("Failed!");
  }

  free_rsa_keypair(kst);
  free_rsa_keypair(peer);

	return 0;
}

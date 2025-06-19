#include <stdio.h>
#include <sodium.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void dump_hex_buff(unsigned char buf[], unsigned int len);

int main(void)
{
    if (sodium_init() < 0) {
      puts("Sodium library couldn't be initialized, it is not safe to use.");
      exit(1);
    }
    
    char *password = "123";
    unsigned long long  password_len = strlen(password);
    char *msg = "Hello";
    const int msg_len = strlen(msg);


  unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
  unsigned char ciphertext[msg_len + crypto_aead_aes256gcm_ABYTES];
  unsigned long long ciphertext_len;
  unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];

  if (crypto_aead_aes256gcm_is_available() == 0) {
      abort(); /* Not available on this CPU */ 
  }

  randombytes_buf(nonce, sizeof nonce);
  
/***********************************************************/
if (crypto_pwhash
    (key, sizeof key, password, strlen(password), key,
     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
     crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
}

/***********************************************************/
/* Encrypt */
crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
                              msg, msg_len,
                              password, password_len-1,
                              NULL, nonce, key);

/***********************************************************/ 
/* Dencrypt */ 
unsigned char decrypted[msg_len];
unsigned long long decrypted_len;
 if (ciphertext_len < crypto_aead_aes256gcm_ABYTES ||
    crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                  NULL,
                                  ciphertext,ciphertext_len,
                                  password,
                                  password_len-1,
                                  nonce, key) != 0) {
}



 
 
 
/***********************************************************/

    puts("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        printf("key:");
        dump_hex_buff(key, sizeof key);

        printf("nonce:");
        dump_hex_buff(nonce, sizeof nonce);	

        printf("encrypted:");
        dump_hex_buff(ciphertext, ciphertext_len);
        printf("encrypted len: %d\n", ciphertext_len );
	
         printf("decrypted data (hex):");
	   dump_hex_buff(decrypted, msg_len); 
	
        printf("decrpyted data (ascii):%s\n", decrypted);
        printf("ciphertext_len:%d\n", ciphertext_len);	


        size_t nonce_maxlen = crypto_sign_PUBLICKEYBYTES * 2 + 1;
        size_t key_maxlen = crypto_sign_SECRETKEYBYTES * 2 + 1;
        size_t ct_maxlen = crypto_sign_BYTES * 2 + 1;

        unsigned char key_hex[sizeof key];
        unsigned char nonce_hex[sizeof nonce];
        unsigned char ct_hex[ciphertext_len];

        sodium_bin2hex(nonce_hex, nonce_maxlen, nonce, sizeof nonce); 	
        sodium_bin2hex(ct_hex, ct_maxlen, ciphertext, ciphertext_len);
        printf("ct_hex: %s/%s \n", ct_hex, nonce_hex); 	
	
        /* sodium_bin2hex(key_hex, key_maxlen, key, crypto_sign_PUBLICKEYBYTES);  */
        /* printf("key_hex: %s\n", key_hex); */

        /*  printf("nonce_hex: %s\n", nonce_hex); */
        //printf("max len: %d\n", crypto_sign_PUBLICKEYBYTES * 2 + 1);		




    int e = EXIT_SUCCESS;
    char *path = "output.txt";

    
    FILE *file = fopen(path, "w");
    if (!file) 
    {
        perror(path);
        return EXIT_FAILURE;
    }

    fprintf(file,"%s/%s \n", ct_hex, nonce_hex); 	     

    
    if (fclose(file)) 
    {
        perror(path);
        return EXIT_FAILURE;
    }

	
    puts("bbbbbbbbbbbbbbbbbbbbb");        
     
    return 0;
}


void dump_hex_buff(unsigned char buf[], unsigned int len)
{
    printf("\n");  
    int i;
    for (i=0; i<len; i++) {
      printf("%02X ", buf[i]);
    }
    printf("\n");
}

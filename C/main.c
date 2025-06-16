#include <stdio.h>
#include <sodium.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void  str2byte(char* bytearray,char* hexstring)
{
  size_t length = strlen(hexstring);
  for (size_t i = 0, j = 0; i < (length / 2); i++, j += 2)
  {
    bytearray[i] = (hexstring[j] % 32 + 9) % 25 * 16 + (hexstring[j+1] % 32 + 9) % 25;
  }

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


/*
  https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm#example-combined-mode
  https://franks42.gitbooks.io/libsodium-doc/content/secret-key_cryptography/aead.html
 */

int main(void)
{
    if (sodium_init() < 0) {
      puts("Sodium library couldn't be initialized, it is not safe to use.");
      exit(1);
    }
    
    char *password = "123";
    char *password_len = strlen(password);
    char *msg = "Hello";
    const int msg_len = strlen(msg);

    
    //const char* hexstring = "1DE7142993816A6A81A7D4A2089A11F5C0A150FBC8E7DC0978D58825CE550000";
 

  unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
  unsigned char ciphertext[msg_len + crypto_aead_aes256gcm_ABYTES];
  unsigned long long ciphertext_len;
  unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];

  
  
  sodium_init();
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
                              password, password_len,
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
                                  password_len,
                                  nonce, key) != 0) {
}

/***********************************************************/

    puts("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        printf("key:");
        dump_hex_buff(key, sizeof key);

        printf("nonce:");
        dump_hex_buff(nonce, sizeof nonce);	

        printf("encrypted:");
        dump_hex_buff(ciphertext, ciphertext_len);
	
        /* printf("decrypted data (hex):");
	   dump_hex_buff(decrypted, msg_len); */
	
        printf("decrpyted data (ascii):%s\n", decrypted);
	
    puts("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");        
     
    return 0;
}


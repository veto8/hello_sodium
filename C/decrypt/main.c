#include <stdio.h>
#include <sodium.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void dump_hex_buff(unsigned char buf[], unsigned int len);


int main(void)
{
    char *password = "123";
    size_t password_len = strlen(password);
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t line_size;
    int line_count = 0;
    char *ct = NULL, *nonce = NULL;

    char *delimiter = "/";
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
  
    if (sodium_init() < 0) {
      puts("Sodium library couldn't be initialized, it is not safe to use.");
      exit(1);
    }

  FILE *fp;

  if ((fp = fopen("output.txt", "r")) == NULL) {
      perror("Error opening file");
      exit(EXIT_FAILURE);
  }

  line_size = getline(&line_buf, &line_buf_size, fp);
  printf("%s",line_buf);


  
// Find the delimiter
    char *delim_pos = strstr(line_buf, delimiter);
    if (delim_pos) {
        size_t ct_len = delim_pos - line_buf;
        ct = malloc(ct_len + 1);
        strncpy(ct, line_buf, ct_len);
        ct[ct_len] = '\0';
        nonce = strdup(delim_pos + strlen(delimiter));
    } else {
        // Delimiter not found, make first the whole buffer
        ct = strdup(line_buf);
        nonce = strdup("");
    }

    printf("CT: %s\n", ct);
    printf("NONCE: %s\n", nonce);




    unsigned char bin[strlen(ct)/2];
    size_t bin_len = 0;
    const char *bin_end = 0;

    if (sodium_hex2bin(bin, sizeof(bin),
                       ct, strlen(ct),
                       NULL, &bin_len, &bin_end) != 0) {
        printf("Invalid hex input!\n");
        return 1;
    }

    
    printf("CT: %s\n", ct);
    dump_hex_buff(bin,bin_len);
    printf("\n");


    unsigned char bin2[strlen(nonce)/2];
    size_t bin2_len = 0;
    const char  *nonce_end = NULL;

    if (sodium_hex2bin(bin2, sizeof(bin2),
                       nonce, strlen(nonce),
                       NULL, &bin2_len, &nonce_end) != 0) {
        printf("Invalid hex input!\n");
        return 1;
    }

    printf("nonce: %s\n", nonce);
    dump_hex_buff(bin2,bin2_len);
    printf("\n");    



if (crypto_pwhash
    (key, sizeof key, password, strlen(password), key,
     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
     crypto_pwhash_ALG_DEFAULT) != 0) {
}





unsigned char decrypted[21];
unsigned long long decrypted_len;
 if (crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                  NULL,
                                  bin, bin_len,
                                  password,
                                  password_len-1,
                                  bin2, key) != 0) {
 printf("...error\n");
 printf("%d\n",decrypted_len);

 
}

 


 printf("decrypted data (hex):");
  dump_hex_buff(decrypted, 4);
 printf("key");  
  dump_hex_buff(key,sizeof key);   

  printf("decrpyted data (ascii):%s\n", decrypted);

 

  

  //printf("decrpyted data (ascii):%s\n", decrypted);    
    

  free(line_buf);
  line_buf = NULL;

  free(ct);
  free(nonce);  
  fclose(fp);

  
     
    return EXIT_SUCCESS;
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

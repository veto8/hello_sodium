#include <stdio.h>
#include <sodium.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>


int main(void)
{
    char *password = "123";
    size_t password_len = strlen(password);
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t line_size;
    int line_count = 0;
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
  free(line_buf);
  line_buf = NULL;

  
  fclose(fp);



  
     
    return EXIT_SUCCESS;
}




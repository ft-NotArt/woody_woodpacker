#include "woody.h"
int main(int argc, char *argv[]) {
	char *to_encrypt = strdup("HELLO !") ;
	size_t encr_size = 7 ;
	char *key = strdup("key") ;
	char *key2 = strdup("key") ; // basically just saving the key, wouldn't do like this in real code
	size_t key_size = 3 ;

	printf("%s\n", to_encrypt) ;
	encrypt(to_encrypt, encr_size, key, key_size) ;
	printf("%s\n", to_encrypt) ;
	decrypt(to_encrypt, encr_size, key2, key_size) ;
	printf("%s\n", to_encrypt) ;
}
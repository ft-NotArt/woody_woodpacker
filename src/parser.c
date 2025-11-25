#include "woody.h"
int main(int argc, char *argv[]) {
	char *to_encrypt = strdup("HELLO WORLD") ;
	size_t encr_size = 11 ;
	char *key = strdup("key") ;
	size_t key_size = 3 ;

	encrypt(to_encrypt, encr_size, key, key_size) ;

	printf("%s\n", to_encrypt) ;
}
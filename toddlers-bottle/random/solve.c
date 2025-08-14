#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!
	printf("%d\n", random ^ 0xcafebabe);

	return 0;
}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void greet_me(char *who)
{
	char name[200];
	strcpy(name, who);
	printf("Hi there %s !!\n",name);
}

int main(int argc, char *argv[])
{
	if (argc < 1)
		exit(1);
	greet_me(argv[1]);

	return 0;
}

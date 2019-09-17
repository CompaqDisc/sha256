#include "sha256.h"

#include <stdint.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv)
{
	const char*	msg	= "abc";
	uint8_t*	digest	= new uint8_t[32]; /*allocate a 256-bit (32-byte) block of memory for the hash*/
	SHA256(digest, std::strlen(msg), (uint8_t*) msg);

	// print the hash
	for (size_t i = 0; i < 32; i++)
		printf("%02x", digest[i]);
	printf("  \"%s\"\n", msg);

	// done with the hash
	delete[] digest;

	return 0;
}

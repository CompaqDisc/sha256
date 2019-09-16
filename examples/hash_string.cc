#include <stdint.h>
#include <cstdio>
#include <cstring>

#include "sha256.h"

int main(int argc, char** argv)
{
	const char*	msg	= "abc";
	uint8_t*	result	= new uint8_t[32]; /*allocate a 256-bit (32-byte) block of memory for the hash*/
	SHA256(result, (uint8_t*) msg, std::strlen(msg));

	// print the hash
	for (size_t i = 0; i < 32; i++)
		printf("%02x", result[i]);
	printf("\n");

	// done with the hash
	delete[] result;

	return 0;
}

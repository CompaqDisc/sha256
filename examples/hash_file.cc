#include <stdint.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>

#include "sha256.h"

int main(int argc, char** argv)
{
	// Exit if no filename was passed.
	if (argc < 2) return -1;

	std::ifstream file(argv[1], std::ios::in | std::ios::binary);
	// Exit if file wasn't opened.
	if (!file) return -1;

	// Get file size.
	file.seekg(0, file.end);
	size_t length = file.tellg();
	file.seekg(0, file.beg);

	uint8_t* digest	= new uint8_t[32]; /*allocate a 256-bit (32-byte) block of memory for the hash*/
	SHA256* algo = new SHA256(digest, length);
	uint8_t* block = new uint8_t[64];
	while (length >= 64)
	{
		length -= 64;
		std::memset(block, 0x00, 64);
		file.read((char*) block, 64);
		algo->submit_block(block);
	}

	std::memset(block, 0x00, 64);
	if (length > 0) file.read((char*) block, length);
	algo->submit_block(block);
	delete[] block;

	// print the hash
	for (size_t i = 0; i < 32; i++)
		printf("%02x", digest[i]);

	printf("  %s\n", argv[1]);

	// done with the hash
	delete[] digest;
	delete algo;

	return 0;
}

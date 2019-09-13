#include <stdint.h>
#include <cstdio>
#include <cstring>

#include "sha256.h"

const uint32_t SHA256::k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256::SHA256(uint8_t* result, const uint8_t* message, size_t length)
{
	// Passed in bytes... convert to bits.
	length *= 8;
	//printf("%d bit message.\n", length);

	uint32_t h[] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
	};

	uint32_t ah[8];

	// Preprocess (padding):
	size_t L = length;
	length += 65;
	size_t K = 512 - (length % 512);
	length += K;

	uint8_t* m = new uint8_t[length / 8];

	//printf("padded to %d bit message.\n", length);
	std::memset(m, 0x00, length / 8);
	std::memcpy(m, message, L / 8);
	// append a single '1' bit
	m[(L / 8)] = 0x80;

	// append L as a 64-bit big-endian integer
	uint64_t len_be64 = L;
	len_be64 = __builtin_bswap64(len_be64);
	std::memcpy(&m[(length / 8) - 8], &len_be64, 8);

	//for (size_t i = 0; i < length / 8; i++)
	//	printf("%02x", m[i]);
	//printf("\n");

	// for each (512-bit) chunk
	for (size_t i = 0; i < length / 512; i++)
	{
		uint8_t* p = &m[(i * 512) / 8];

		// create a 64-entry message shcedule array w[0..63] of 32-bit words
		uint32_t w[64] = { 0 };

		// copy chunk into first 16 words w[0..15] of the message schedule array
		//std::memcpy(&w[0], &m[(i*512)/8], 64);
		for (size_t i = 0; i < 16; i++)
		{
			w[i] = (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 | (uint32_t) p[3];
			p += 4;
		}

		// Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
		for (size_t i = 16; i < 64; i++)
		{
			uint32_t s0 = ROR(w[i - 15],  7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >>  3);
			uint32_t s1 = ROR(w[i -  2], 17) ^ ROR(w[i -  2], 19) ^ (w[i -  2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		// Initialize working variables to current hash value:
		std::memcpy(&ah, &h, 32);

		// Compression function main loop:
		for (size_t i = 0; i < 64; i++)
		{
			uint32_t S1	= ROR(ah[4], 6) ^ ROR(ah[4], 11) ^ ROR(ah[4], 25);
			uint32_t ch	= (ah[4] & ah[5]) ^ ((~ah[4]) & ah[6]);
			uint32_t temp1	= ah[7] + S1 + ch + k[i] + w[i];
			uint32_t S0	= ROR(ah[0], 2) ^ ROR(ah[0], 13) ^ ROR(ah[0], 22);
			uint32_t maj	= (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
			uint32_t temp2	= S0 + maj;

			ah[7] = ah[6];
			ah[6] = ah[5];
			ah[5] = ah[4];
			ah[4] = ah[3] + temp1;
			ah[3] = ah[2];
			ah[2] = ah[1];
			ah[1] = ah[0];
			ah[0] = temp1 + temp2;
		}

		h[0] = h[0] + ah[0];
		h[1] = h[1] + ah[1];
		h[2] = h[2] + ah[2];
		h[3] = h[3] + ah[3];
		h[4] = h[4] + ah[4];
		h[5] = h[5] + ah[5];
		h[6] = h[6] + ah[6];
		h[7] = h[7] + ah[7];
	}

	// copy final hash value.
	for (size_t i = 0; i < 8; i++)
	{
		uint32_t swizzle = __builtin_bswap32(h[i]);
		std::memcpy(&result[i*4], &swizzle, 4);
	}

	delete[] m;
}

uint32_t SHA256::ROR(uint32_t value, size_t count)
{
	return value >> count | value << (32 - count);
}

int main(int argc, char** argv)
{
	//if (argc < 2)
	//	return -1;

	const char*	msg	= "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	// Allocate a 256-bit (32-byte) region of memory.
	uint8_t*	result	= new uint8_t[32];
	SHA256(result, (uint8_t*) msg, std::strlen(msg));

	// Print our sha256sum.
	for (size_t i = 0; i < 32; i++)
		printf("%02x", result[i]);
	printf("\n");
	
	delete[] result;

	return 0;
}
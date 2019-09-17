#pragma once

#include <stdint.h>
#include <algorithm>
#include <cstring>
#include <cstdio>

class SHA256
{
public:
	static const uint32_t	k[64];
	static uint32_t		h[8];
	static uint32_t		ah[8];
	static uint8_t*		digest;
	static size_t		length;
	static size_t		blocks;

	SHA256(uint8_t* digest, size_t length, const uint8_t* data);
	SHA256(uint8_t* digest, size_t length);
	void submit_block(uint8_t* data);

	uint32_t ROR(uint32_t value, size_t count);
};

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

uint32_t SHA256::h[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

uint32_t SHA256::ah[] = {
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
};

uint8_t* SHA256::digest = nullptr;
size_t SHA256::length = -1;
size_t SHA256::blocks = -1;

SHA256::SHA256(uint8_t* digest, size_t length, const uint8_t* data)
{
	SHA256(digest, length);
	
	uint8_t* block = new uint8_t[64];
	for (size_t i = 0; i < SHA256::blocks; i++)
	{
		std::memset(block, 0, 64);
		std::memcpy(block, data, (length < 64) ? length : 64);
		SHA256::submit_block(block);
		length -= 64;
	}
	delete[] block;
	return;
}

SHA256::SHA256(uint8_t* _digest, size_t _length)
{
	digest = _digest;
	length = _length;
	// Preprocess (padding):
	size_t len_bits = (length/*bytes*/ * 8/*bits*/) + 1/*single '1' bit*/ + 64;/*embedded length*/
	size_t K = 512 - (len_bits % 512);
	len_bits += K;
	blocks = (len_bits / 512);
}

void SHA256::submit_block(uint8_t* data)
{
	blocks--;
	if (blocks == 0)
	{
		// Place our '1' bit and our size into the final block.
		data[length % 64] = 0x80;
		((uint64_t*) data)[7] /*pointer to beginning of last 64-bits of array*/ = __builtin_bswap64(length * 8); /*now in big endian format!*/
	}

	uint32_t* p = (uint32_t*) data;

	// create a 64-entry message shcedule array w[0..63] of 32-bit words
	uint32_t w[64] = { 0 };

	// copy chunk into first 16 words w[0..15] of the message schedule array
	for (size_t i = 0; i < 16; i++)
	{
		w[i] = __builtin_bswap32(*p); /*interpret byte-stream (that we have a dword [32-bit] pointer to) as big-endian*/
		p++;
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

	if (blocks == 0)
	{
		// Copy final digest.
		for (size_t i = 0; i < 8; i++)
		{
			// Index as uint32_t array and place big-endian eqivalent values.
			((uint32_t*) digest)[i] = __builtin_bswap32(h[i]);
		}
	}
}

uint32_t SHA256::ROR(uint32_t value, size_t count)
{
	return value >> count | value << (32 - count);
}
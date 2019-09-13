class SHA256
{
public:
	static const uint32_t k[64];

	SHA256(uint8_t* result, const uint8_t* message, size_t length_bits);

	uint32_t ROR(uint32_t value, size_t count);
};
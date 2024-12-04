namespace PacketCryptProof {
	enum RHOpCodes : byte {
		OpCode_INVALID_ZERO,

		OpCode_POPCNT8, OpCode_POPCNT16, OpCode_POPCNT32,
		OpCode_CLZ8, OpCode_CLZ16, OpCode_CLZ32,
		OpCode_CTZ8, OpCode_CTZ16, OpCode_CTZ32,

		OpCode_BSWAP16, OpCode_BSWAP32,

		OpCode_ADD8, OpCode_ADD16, OpCode_ADD32,
		OpCode_SUB8, OpCode_SUB16, OpCode_SUB32,
		OpCode_SHLL8, OpCode_SHLL16, OpCode_SHLL32,
		OpCode_SHRL8, OpCode_SHRL16, OpCode_SHRL32,
		OpCode_SHRA8, OpCode_SHRA16, OpCode_SHRA32,
		OpCode_ROTL8, OpCode_ROTL16, OpCode_ROTL32,
		OpCode_MUL8, OpCode_MUL16, OpCode_MUL32,

		OpCode_AND, OpCode_OR, OpCode_XOR,

		OpCode_ADD8C, OpCode_ADD16C, OpCode_ADD32C,
		OpCode_SUB8C, OpCode_SUB16C, OpCode_SUB32C,
		OpCode_MUL8C, OpCode_MUL16C, OpCode_MUL32C,
		OpCode_MULSU8C, OpCode_MULSU16C, OpCode_MULSU32C,
		OpCode_MULU8C, OpCode_MULU16C, OpCode_MULU32C,

		OpCode_ADD64,
		OpCode_SUB64,
		OpCode_SHLL64,
		OpCode_SHRL64,
		OpCode_SHRA64,
		OpCode_ROTL64,
		OpCode_ROTR64,
		OpCode_MUL64,

		OpCode_ADD64C,
		OpCode_SUB64C,
		OpCode_MUL64C,
		OpCode_MULSU64C,
		OpCode_MULU64C,

		OpCode_IN,
		OpCode_MEMORY,

		OpCode_LOOP,
		OpCode_IF_LIKELY,
		OpCode_IF_RANDOM,
		OpCode_JMP,
		OpCode_END,
	}
}

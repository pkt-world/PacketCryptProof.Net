using System;
using System.Runtime.InteropServices;

namespace PktNode {
	internal class Validate {
		const int PacketCrypt_NUM_ANNS = 4;

		const int Validate_checkBlock_OK = 0;
		const int Validate_checkBlock_SHARE_OK = 1 << 8;
		const int Validate_checkBlock_ANN_INVALID_ = 2 << 8;
		const int Validate_checkBlock_ANN_INSUF_POW_ = 3 << 8;
		const int Validate_checkBlock_ANN_SIG_INVALID_ = 4 << 8;
		const int Validate_checkBlock_ANN_CONTENT_INVALID_ = 5 << 8;
		const int Validate_checkBlock_PCP_INVAL = 6 << 8;
		const int Validate_checkBlock_PCP_MISMATCH = 7 << 8;
		const int Validate_checkBlock_INSUF_POW = 8 << 8;
		const int Validate_checkBlock_BAD_COINBASE = 9 << 8;

		static int Validate_checkBlock_ANN_INVALID(int x) { return Validate_checkBlock_ANN_INVALID_ | x; }
		static int Validate_checkBlock_ANN_INSUF_POW(int x) { return Validate_checkBlock_ANN_INSUF_POW_ | x; }

		const UInt32 PacketCrypt_Coinbase_MAGIC = 0x0211f909;

		static bool Work_check(Byte[] hash, int target) {
			const uint CB_MAX_TARGET = 0x207FFFFF;
			// Get trailing zero bytes
			int zeroBytes = target >> 24;
			// Check target is less than or equal to maximum.
			if (target > CB_MAX_TARGET) return false;
			// Modify the target to the mantissa (significand).
			target &= 0x00FFFFFF;
			// Check mantissa is below 0x800000.
			if (target > 0x7FFFFF) return false;
			// Fail if hash is above target. First check leading bytes to significant part.
			// As the hash is seen as little-endian, do this backwards.
			for (int x = 0; x < 32 - zeroBytes; x++)
				// A byte leading to the significant part is not zero
				if (hash[31 - x] != 0) return false;
			// Check significant part
			int significantPart = hash[zeroBytes - 1] << 16;
			significantPart |= hash[zeroBytes - 2] << 8;
			significantPart |= hash[zeroBytes - 3];
			if (significantPart >= target) return false;
			return true;
		}

		public static String Validate_checkBlock_outToString(int code) {
			switch (code) {
				case Validate_checkBlock_OK: return "Validate_checkBlock_OK"; //NULL
				case Validate_checkBlock_SHARE_OK: return "Validate_checkBlock_SHARE_OK";
				case Validate_checkBlock_PCP_INVAL: return "Validate_checkBlock_PCP_INVAL";
				case Validate_checkBlock_PCP_MISMATCH: return "Validate_checkBlock_PCP_MISMATCH";
				case Validate_checkBlock_INSUF_POW: return "Validate_checkBlock_INSUF_POW";
				case Validate_checkBlock_BAD_COINBASE: return "Validate_checkBlock_BAD_COINBASE";
			}
			int index = code & 0xFF;
			switch (code & 0xFFFFFF00) {
				case Validate_checkBlock_ANN_INVALID_: return "Validate_checkBlock_ANN_INVALID(" + index.ToString() + ")";
				case Validate_checkBlock_ANN_INSUF_POW_: return "Validate_checkBlock_ANN_INSUF_POW(" + index.ToString() + ")";
				case Validate_checkBlock_ANN_SIG_INVALID_: return "Validate_checkBlock_ANN_SIG_INVALID(" + index.ToString() + ")";
				case Validate_checkBlock_ANN_CONTENT_INVALID_: return "Validate_checkBlock_ANN_CONTENT_INVALID(" + index.ToString() + ")";
			}
			return "Validate_checkBlock_UNKNOWN_ERROR(" + code.ToString() + ")";
		}
	}
}

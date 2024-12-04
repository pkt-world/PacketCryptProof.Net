using System.Numerics;

namespace PacketCryptProof {
	public static class Difficulty {
		public static BigInteger FromCompact(UInt32 nCompact) {
			uint nSize = nCompact >> 24;
			bool fNegative = (nCompact & 0x00800000) != 0;
			uint nWord = nCompact & 0x007fffff;
			BigInteger bn;
			if (nSize <= 3) {
				nWord >>= 8 * (int)(3 - nSize);
				bn = nWord;
			} else {
				bn = nWord;
				bn <<= 8 * (int)(nSize - 3);
			}
			if (fNegative) bn *= -1;
			return bn;
		}

		public static UInt32 ToCompact(BigInteger bn) {
			int nSize = bn.GetByteCount();
			uint nCompact;
			if (nSize <= 3)
				nCompact = (uint)bn << (8 * (3 - nSize));
			else {
				BigInteger x = bn >> (8 * (nSize - 3));
				nCompact = (uint)x;
			}
			// The 0x00800000 bit denotes the sign.
			// Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
			if ((nCompact & 0x00800000) != 0) {
				nCompact >>= 8;
				nSize++;
			}
			nCompact |= (uint)nSize << 24;
			nCompact |= (bn.Sign < 0 ? 0x00800000 : 0u);
			return nCompact;
		}

		static readonly BigInteger bn256 = new BigInteger(1) << 256;
		static BigInteger bnWorkForDiff(BigInteger diff) {
			return bn256 / (diff + 1);
		}
		static BigInteger bnDiffForWork(BigInteger work) {
			// if work is zero then target is maximum (minimum difficulty)
			if (work.IsZero) return bn256;
			return (bn256 - work) / work;
		}

		static BigInteger getEffectiveWork(BigInteger blockWork, BigInteger annWork, UInt64 annCount, UInt32 pcpVersion) {
			if (annWork.IsZero || annCount == 0) {
				// This is work *required* so when there is no work and no announcements
				// that work is "infinite".
				return bn256;
			}

			BigInteger workOut = blockWork;

			// workOut = workOut**3
			workOut = workOut * workOut;
			workOut = workOut * blockWork;

			if (pcpVersion >= 2) {
				// difficulty /= 1024
				workOut >>= 10;
			}

			// workOut /= annWork
			workOut = workOut / annWork;

			BigInteger bnAnnCount = annCount;
			if (pcpVersion >= 2) {
				bnAnnCount = bnAnnCount * bnAnnCount;
			}

			// workOut /= annCount
			workOut = workOut / bnAnnCount;
			return workOut;
		}

		public static UInt32 GetEffectiveBlockTarget(UInt32 blockTarget, UInt32 annTarget, UInt64 annCount, UInt32 pcpVersion) {
			BigInteger x = FromCompact(blockTarget);
			BigInteger bnBlockWork = bnWorkForDiff(x);

			x = FromCompact(annTarget);
			BigInteger bnAnnWork = bnWorkForDiff(x);

			x = getEffectiveWork(bnBlockWork, bnAnnWork, annCount, pcpVersion);

			bnBlockWork = bnDiffForWork(x);

			UInt32 tgt = ToCompact(bnBlockWork);
			if (tgt > 0x207fffff) return 0x207fffff;
			return tgt;
		}

		public static UInt32 DegradeAnnouncementTarget(UInt32 annTar, UInt32 annAgeBlocks, UInt32 pcpVersion) {
			const int Conf_PacketCrypt_ANN_WAIT_PERIOD = 3;
			if (pcpVersion >= 2) {
				if (annAgeBlocks < Conf_PacketCrypt_ANN_WAIT_PERIOD) return 0xffffffff;
				if (annAgeBlocks == Conf_PacketCrypt_ANN_WAIT_PERIOD) return annTar;
				annAgeBlocks -= Conf_PacketCrypt_ANN_WAIT_PERIOD;
				BigInteger bnAnnTar = FromCompact(annTar);
				bnAnnTar <<= (int)annAgeBlocks;
				if (bnAnnTar.GetBitLength() > 255) return 0xffffffff;
				return ToCompact(bnAnnTar); ;
			} else {
				if (annAgeBlocks < Conf_PacketCrypt_ANN_WAIT_PERIOD) return 0xffffffff;
				BigInteger bnAnnTar = FromCompact(annTar);
				if (annAgeBlocks == Conf_PacketCrypt_ANN_WAIT_PERIOD) return ToCompact(bnAnnTar);
				annAgeBlocks -= Conf_PacketCrypt_ANN_WAIT_PERIOD;
				BigInteger bnAnnWork = bnWorkForDiff(bnAnnTar);
				bnAnnWork /= annAgeBlocks;
				var bnAnnAgedTar = bnDiffForWork(bnAnnWork);
				var ret = ToCompact(bnAnnAgedTar);
				if (ret > 0x207fffff) return 0xffffffff;
				return ret;
			}
		}

		// IsAnnMinDiffOk is kind of a sanity check to make sure that the miner doesn't provide
		// "silly" results which might trigger wrong behavior from the diff computation
		public static bool IsMinAnnDiffOk(UInt32 target, UInt32 packetCryptVersion) {
			if (packetCryptVersion >= 2) {
				if (target == 0 || target > 0x207fffff) return false;
				BigInteger big = FromCompact(target);
				if (big.IsZero || big.Sign <= 0) return false;
				BigInteger work = bnWorkForDiff(big);
				return work.Sign > 0 && work < bn256;
			}
			if (target == 0 || target > 0x20ffffff) return false;
			{
				var work = bnWorkForDiff(FromCompact(target));
				return work.Sign > 0 && work < bn256;
			}
		}

		public static Boolean CheckHash(Span<Byte> hash, UInt32 target) {
			if (hash.Length != 32) throw new ArgumentOutOfRangeException("hash");
			const uint CB_MAX_TARGET = 0x207FFFFF;
			// Get trailing zero bytes
			int zeroBytes = (int)(target >> 24);
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
	}
}

namespace PacketCryptProof {
	public class Validator {
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
		static int Validate_checkBlock_ANN_SIG_INVALID(int x) { return Validate_checkBlock_ANN_SIG_INVALID_ | x; }

		const UInt32 PacketCrypt_Coinbase_MAGIC = 0x0211f909;

		public static int ValidateBlock(
			ReadOnlySpan<Byte> blockHeader, UInt32 blockHeight, UInt32 pcpNonce, UInt32 pcpVersion,
			ReadOnlySpan<Byte> ann0, ReadOnlySpan<Byte> ann1, ReadOnlySpan<Byte> ann2, ReadOnlySpan<Byte> ann3,
			ReadOnlySpan<Byte> ann0sig, ReadOnlySpan<Byte> ann1sig, ReadOnlySpan<Byte> ann2sig, ReadOnlySpan<Byte> ann3sig,
			ReadOnlySpan<Byte> annProof, ReadOnlySpan<Byte> contentProof, ReadOnlySpan<Byte> annMerkleRoot,
			UInt32 annLeastWork, UInt64 annCount, Func<UInt32, Byte[]> getBlockHashCb) {

			if (blockHeader.Length != 80) throw new ArgumentOutOfRangeException("blockHeader");
			if (ann0.Length != 1024) throw new ArgumentOutOfRangeException("ann0");
			if (ann1.Length != 1024) throw new ArgumentOutOfRangeException("ann1");
			if (ann2.Length != 1024) throw new ArgumentOutOfRangeException("ann2");
			if (ann3.Length != 1024) throw new ArgumentOutOfRangeException("ann3");
			if (annMerkleRoot.Length != 32) throw new ArgumentOutOfRangeException("annMerkleRoot");

			if (pcpVersion > 1 && blockHeight < 113949) return Validate_checkBlock_PCP_MISMATCH;
			if (pcpVersion < 2 && blockHeight > 122621) return Validate_checkBlock_PCP_MISMATCH;

			if (!CheckAnn.CheckSignature(ann0, ann0sig)) return Validate_checkBlock_ANN_SIG_INVALID(0);
			if (!CheckAnn.CheckSignature(ann1, ann1sig)) return Validate_checkBlock_ANN_SIG_INVALID(1);
			if (!CheckAnn.CheckSignature(ann2, ann2sig)) return Validate_checkBlock_ANN_SIG_INVALID(2);
			if (!CheckAnn.CheckSignature(ann3, ann3sig)) return Validate_checkBlock_ANN_SIG_INVALID(3);

			Span<Byte> cpbuf = stackalloc Byte[4 * 32];
			Span<Boolean> hascp = stackalloc Boolean[4];
			hascp.Fill(false);
			{
				//contentProofIdx2
				Span<Byte> buf = stackalloc byte[32];
				Crypto.generichash_blake2b(buf, blockHeader);
				UInt32 proofIdx = BitConverter.ToUInt32(buf) ^ pcpNonce;

				//SplitContentProof
				if (pcpVersion <= 1) {
					int offset = 0;
					for (int i = 0; i < 4; i++) {
						ReadOnlySpan<Byte> ann = i switch { 0 => ann0, 1 => ann1, 2 => ann2, 3 => ann3 };
						UInt32 content_length = CheckAnn.GetContentLength(ann);
						if (content_length <= 32) continue;
						ReadOnlySpan<Byte> cp = SplitContentProof(contentProof, proofIdx, ref offset, content_length);
						if (cp == null) return Validate_checkBlock_ANN_CONTENT_INVALID_ | 0;
						if (!CheckAnn.CheckContentProof(ann, proofIdx, cp)) return Validate_checkBlock_ANN_CONTENT_INVALID_ | 0;
						cp.Slice(0, 32).CopyTo(cpbuf.Slice(i * 32, 32));
						hascp[i] = true;
					}
					if (offset != contentProof.Length) throw new Exception("SplitContentProof: dangling bytes after the content proof");
				} else {
					if (contentProof != null) return Validate_checkBlock_PCP_INVAL;
				}
			}

			if (!Difficulty.IsMinAnnDiffOk(annLeastWork, pcpVersion)) return Validate_checkBlock_BAD_COINBASE;

			// Check that final work result meets difficulty requirement
			Span<UInt64> annIndexes = stackalloc UInt64[4];
			int chk = checkPcHash(blockHeader, pcpNonce, pcpVersion, ann0, ann1, ann2, ann3, hascp[0] ? cpbuf.Slice(0, 32) : null, hascp[1] ? cpbuf.Slice(32, 32) : null, hascp[2] ? cpbuf.Slice(64, 32) : null, hascp[3] ? cpbuf.Slice(96, 32) : null, annLeastWork, annCount, annIndexes);

			Span<Byte> annHashes = stackalloc byte[4 * 32];

			// Validate announcements
			for (int i = 0; i < PacketCrypt_NUM_ANNS; i++) {
				ReadOnlySpan<Byte> ann = i switch { 0 => ann0, 1 => ann1, 2 => ann2, 3 => ann3 };
				UInt32 parentBlockHeight = CheckAnn.GetParentBlockHeight(ann);
				if (parentBlockHeight > blockHeight) return Validate_checkBlock_ANN_INVALID(i);
				if (getBlockHashCb != null) {
					Byte[] blockHash = getBlockHashCb(parentBlockHeight);
					if (blockHash == null) return Validate_checkBlock_ANN_INVALID(i);
					if (CheckAnn.Validate(ann, blockHash, pcpVersion) != 0) return Validate_checkBlock_ANN_INVALID(i);
				}
				UInt32 nWorkBits = CheckAnn.GetWorkBits(ann);
				UInt32 effectiveAnnTarget = Difficulty.DegradeAnnouncementTarget(nWorkBits, blockHeight - parentBlockHeight, pcpVersion);
				if (blockHeight < 3) effectiveAnnTarget = nWorkBits;
				if (effectiveAnnTarget > annLeastWork) return Validate_checkBlock_ANN_INSUF_POW(i);
				Crypto.generichash_blake2b(annHashes.Slice(i * 32, 32), ann);
			}

			// hash PacketCryptProof
			Span<Byte> pcpHash = stackalloc Byte[32];
			if (PcCompress_t.PacketCryptProof_hashProof(pcpHash, annHashes, annCount, annIndexes, annProof) != 0) return Validate_checkBlock_PCP_INVAL;

			// compare PacketCryptProof root hash to CoinbaseCommitment
			if (!pcpHash.SequenceEqual(annMerkleRoot)) return Validate_checkBlock_PCP_MISMATCH;

			return chk;
		}

		private static ReadOnlySpan<Byte> SplitContentProof(ReadOnlySpan<Byte> contentProof, UInt32 proofIdx, ref int offset, UInt32 contentLength) {
			if (contentLength <= 32) return null;
			var totalBlocks = contentLength / 32;
			if (totalBlocks * 32 < contentLength) totalBlocks++;
			var blockToProve = proofIdx % totalBlocks;
			var depth = CheckAnn.Util_log2ceil(totalBlocks);
			var length = 32;
			UInt32 blockSize = 32;
			for (int j = 0; j < depth; j++) {
				if (blockSize * (blockToProve ^ 1) >= contentLength) {
					blockToProve >>= 1;
					blockSize <<= 1;
					continue;
				}
				length += 32;
				blockToProve >>= 1;
				blockSize <<= 1;
			}
			var ret = contentProof.Slice(offset, length).ToArray();
			offset += length;
			return ret;
		}

		public static String ResultToString(int code) {
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

		private static int checkPcHash(
			ReadOnlySpan<Byte> blockHeader, UInt32 pcpNonce, UInt32 pcpVersion,
			ReadOnlySpan<Byte> ann0, ReadOnlySpan<Byte> ann1, ReadOnlySpan<Byte> ann2, ReadOnlySpan<Byte> ann3,
			ReadOnlySpan<Byte> cp0, ReadOnlySpan<Byte> cp1, ReadOnlySpan<Byte> cp2, ReadOnlySpan<Byte> cp3,
			UInt32 annLeastWork, UInt64 annCount, Span<ulong> indexesOut) {

			Byte[] hdrHash = new byte[32];
			Crypto.generichash_blake2b(hdrHash, blockHeader);
			Byte[] pcState = new byte[2048];
			CryptoCycle.Initialize(pcState, hdrHash, pcpNonce);
			if (indexesOut != null) indexesOut[0] = CryptoCycle.GetItemNumber(pcState);
			CryptoCycle.Update(pcState, ann0, cp0 == null ? null : cp0.Slice(0, 32));
			if (indexesOut != null) indexesOut[1] = CryptoCycle.GetItemNumber(pcState);
			CryptoCycle.Update(pcState, ann1, cp1 == null ? null : cp1.Slice(0, 32));
			if (indexesOut != null) indexesOut[2] = CryptoCycle.GetItemNumber(pcState);
			CryptoCycle.Update(pcState, ann2, cp2 == null ? null : cp2.Slice(0, 32));
			if (indexesOut != null) indexesOut[3] = CryptoCycle.GetItemNumber(pcState);
			CryptoCycle.Update(pcState, ann3, cp3 == null ? null : cp3.Slice(0, 32));

			CryptoCycle.ScalarMult(pcState);
			CryptoCycle.Finalize(pcState);
			UInt32 nBits = BitConverter.ToUInt32(blockHeader.Slice(72, 4));
			if (isWorkOk(pcState, annLeastWork, annCount, nBits, pcpVersion)) return Validate_checkBlock_OK;
			//if (shareTarget != 0 && isWorkOk(&pcState, cb, shareTarget)) return Validate_checkBlock_SHARE_OK;
			return Validate_checkBlock_INSUF_POW;
		}

		private static bool isWorkOk(Span<Byte> ccState, UInt32 annLeastWork, UInt64 annCount, UInt32 target, UInt32 pcpVersion) {
			UInt32 effectiveTarget = Difficulty.GetEffectiveBlockTarget(target, annLeastWork, annCount, pcpVersion);
			return Difficulty.CheckHash(ccState.Slice(0, 32), effectiveTarget);
		}
	}
}

using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;

namespace PacketCryptProof {
	internal static partial class CheckAnn {
		public static Byte GetVersion(ReadOnlySpan<Byte> buffer) {
			return buffer[0];
		}

		public static UInt32 GetWorkBits(ReadOnlySpan<Byte> buffer) {
			return BitConverter.ToUInt32(buffer.Slice(8, 4));
		}

		public static UInt32 GetParentBlockHeight(ReadOnlySpan<Byte> buffer) {
			return BitConverter.ToUInt32(buffer.Slice(12, 4));
		}

		public static UInt32 GetContentLength(ReadOnlySpan<Byte> buffer) {
			return BitConverter.ToUInt32(buffer.Slice(20, 4));
		}

		public static UInt32 GetSoftNonce(ReadOnlySpan<Byte> ann) {
			return ((UInt32)ann[3] << 16) | ((UInt32)ann[2] << 8) | (UInt32)ann[1];
		}

		static int Util_log2floor(UInt64 x) {
			return 63 - BitOperations.LeadingZeroCount(x);
		}

		public static int Util_log2ceil(UInt64 x) {
			return ((x & (x - 1)) != 0 ? 1 : 0) + CheckAnn.Util_log2floor(x);
		}

		public static UInt32 GetMaxSoftNonce(UInt32 target) {
			int bits = (22 - Util_log2floor(target & 0x007fffff)) + ((0x20 - (int)(target >> 24)) * 8) + 10;
			return (bits >= 24) ? 0x00ffffffU : (0x00ffffffU >> (24 - bits));
		}

		public static Boolean HasSigningKey(ReadOnlySpan<Byte> buffer) {
			return BitConverter.ToUInt64(buffer.Slice(56, 8)) != 0 ||
				BitConverter.ToUInt64(buffer.Slice(56 + 8, 8)) != 0 ||
				BitConverter.ToUInt64(buffer.Slice(56 + 16, 8)) != 0 ||
				BitConverter.ToUInt64(buffer.Slice(56 + 24, 8)) != 0;
		}

		const int Validate_checkAnn_OK = 0;
		const int Validate_checkAnn_INVAL = 1;
		const int Validate_checkAnn_INVAL_ITEM4 = 2;
		const int Validate_checkAnn_INSUF_POW = 3;
		const int Validate_checkAnn_SOFT_NONCE_HIGH = 4;
		const int Validate_checkAnn_ANN_VERSION_NOT_ALLOWED = 5;
		const int Validate_checkAnn_ANN_VERSION_MISMATCH = 6;

		const int Announce_MERKLE_DEPTH = 13;
		const int Announce_TABLE_SZ = (1 << Announce_MERKLE_DEPTH);

		public static Boolean CheckSignature(ReadOnlySpan<Byte> announcement, ReadOnlySpan<Byte> signature) {
			if (!HasSigningKey(announcement)) {
				return true;
			} else if (signature == null) {
				return false;
			} else if (!Crypto.sign_ed25519_verify(signature, announcement, announcement.Slice(56, 32))) {
				return false;
			}
			return true;
		}

		[LibraryImport("packetcrypt.dll")]
		private static partial int Validate_checkAnn(Span<Byte> annHashOut, ReadOnlySpan<Byte> pcAnn, ReadOnlySpan<Byte> parentBlockHash, Span<UInt32> vctx);

		public static int Validate(ReadOnlySpan<Byte> announcement, Span<Byte> parentBlockHash, UInt32 pcpVersion) {
			if (announcement.Length != 1024) throw new ArgumentOutOfRangeException("announcement");
			if (parentBlockHash.Length != 32) throw new ArgumentOutOfRangeException("parentBlockHash");

			Span<Byte> caAnnHashOut = new Byte[32];
			int caret = Validate_checkAnn(caAnnHashOut, announcement, parentBlockHash, new UInt32[2048 + 1]);

			Span<Byte> annHash = new Byte[32];
			Crypto.generichash_blake2b(annHash, announcement);

			UInt32 version = GetVersion(announcement);
			if (version > 0 && GetParentBlockHeight(announcement) < 103869) return Validate_checkAnn_ANN_VERSION_NOT_ALLOWED;
			if (pcpVersion > 1 && version == 0) return Validate_checkAnn_ANN_VERSION_MISMATCH;

			Span<Byte> _ann = new Byte[1024];
			ReadOnlySpan<Byte> ann = announcement;
			ann.Slice(0, 88).CopyTo(_ann); //Copy header
			Span<Byte> _ann_merkleProof = _ann.Slice(88, 896);
			parentBlockHash.CopyTo(_ann_merkleProof.Slice(0, 32)); //merkleProof.thirtytwos[0]
			_ann_merkleProof.Slice(32, 32).Clear(); //merkleProof.thirtytwos[1]
			//_ann.Slice(4, 12).Clear(); //Clear softnonce
			_ann.Slice(1, 3).Clear(); //Clear softnonce

			Span<Byte> annHash0 = stackalloc Byte[64];
			Crypto.generichash_blake2b(annHash0, _ann.Slice(0, 88 + 64));

			ann.Slice(88 + 64 * 13, 64).CopyTo(_ann.Slice(88 + 64 * 0, 64)); //Buf_OBJCPY(&_ann.merkleProof.sixtyfours[0], &ann->merkleProof.sixtyfours[13]);

			Span<Byte> annHash1 = stackalloc Byte[64];
			Crypto.generichash_blake2b(annHash1, _ann.Slice(0, 88 + 64));

			UInt32 softNonce = GetSoftNonce(ann);

			UInt32 workBits = GetWorkBits(ann);

			UInt32[] prog = null;
			UInt32[] progmem = null;
			Span<Byte> v1Seed = stackalloc Byte[2 * 64];

			if (version > 0) {
				UInt32 softNonceMax = GetMaxSoftNonce(workBits);

				if (softNonce > softNonceMax) return Validate_checkAnn_SOFT_NONCE_HIGH;

				ann.Slice(88 + 64 * Announce_MERKLE_DEPTH, 64).CopyTo(v1Seed.Slice(64 * 0, 64)); //Buf_OBJCPY(&v1Seed[0], &ann->merkleProof.sixtyfours[Announce_MERKLE_DEPTH]);
				annHash0.CopyTo(v1Seed.Slice(64 * 1, 64)); //Buf_OBJCPY(&v1Seed[1], &annHash0);
				Crypto.generichash_blake2b(v1Seed.Slice(0, 64), v1Seed); //Hash_COMPRESS64_OBJ(&v1Seed[0], &v1Seed);

				progmem = new UInt32[8192 / 4];
				prog = Announce_createProg(progmem, v1Seed.Slice(0, 32));
			}

			Byte[] state = new Byte[2048];
			CryptoCycle.Initialize(state, annHash1.Slice(0, 32), softNonce);
			ulong itemNo = 0;
			UInt32[] item = new UInt32[1024 / 4];
			Span<Byte> item_bytes = MemoryMarshal.AsBytes(new Span<UInt32>(item));
			for (int i = 0; i < 4; i++) {
				itemNo = CryptoCycle.GetItemNumber(state) % Announce_TABLE_SZ;
				if (version > 0) {
					Announce_mkitem2(itemNo, item_bytes, v1Seed.Slice(32, 32), prog, progmem);
				} else {
					MkItem((uint)itemNo, item_bytes, annHash0.Slice(0, 32));
					var prog_2 = RandGen.Generate(item_bytes.Slice(32 * 31, 32));
					if (!RandHashInterpreter.Interpret(prog_2, state, item, 4)) return -1;
				}
				CryptoCycle.Update(state, item_bytes, null);
			}

			CryptoCycle.Finalize(state);

			if (version > 0) {
				ann.CopyTo(_ann);
				ann = _ann;
				Announce_crypt(_ann, state);
				if (ann.Slice(984, 40).ContainsAnyExcept((Byte)0)) return Validate_checkAnn_INVAL_ITEM4;

				// Need to re-compute the item because we are proving the original value
				prog = Announce_createProg(progmem, annHash0.Slice(0, 32));
				Announce_mkitem2(itemNo, item_bytes, annHash0.Slice(32, 32), prog, progmem);
			} else {
				if (!item_bytes.Slice(0, 40).SequenceEqual(ann.Slice(88 + 896, 40))) return Validate_checkAnn_INVAL_ITEM4;
			}

			Span<Byte> itemHash = stackalloc Byte[64];
			Crypto.generichash_blake2b(itemHash, item_bytes);
			if (!AnnMerkle__isItemValid(Announce_MERKLE_DEPTH, ann.Slice(88), itemHash, (int)itemNo)) return Validate_checkAnn_INVAL;

			if (!Difficulty.CheckHash((new Span<Byte>(state)).Slice(0, 32), workBits)) return Validate_checkAnn_INSUF_POW;

			Debug.Assert(caAnnHashOut.SequenceEqual((new Span<Byte>(state)).Slice(0, 32)));

			Debug.Assert(caret == 0);

			return Validate_checkAnn_OK;
		}

		private static UInt32[] Announce_createProg(Span<UInt32> memory, Span<Byte> seed) {
			if (memory.Length != 8192 / 4) throw new ArgumentOutOfRangeException("memory");
			CryptoCycle.Hash_expand(MemoryMarshal.AsBytes(memory), seed, 0);
			UInt32[] prog = RandGen.Generate(seed);
			prog.CopyTo(memory);
			return prog;
		}

		private static int Announce_mkitem2(UInt64 itemNo, Span<Byte> item, Span<Byte> seed, Span<UInt32> prog, Span<UInt32> progmem) {
			Byte[] state = new Byte[2048];
			CryptoCycle.Initialize(state, seed, itemNo);
			var memoryBeginning = itemNo % (uint)(progmem.Length - 256);
			var memorySlice = progmem.Slice((int)memoryBeginning, 256);
			if (!RandHashInterpreter.Interpret(prog, state, memorySlice, 2)) return -1;
			CryptoCycle.MakeFuzzable(state);
			CryptoCycle.Crypt(state);
			(new Span<Byte>(state)).Slice(0, 1024).CopyTo(item);
			return 0;
		}

		private static void Announce_crypt(Span<Byte> ann, ReadOnlySpan<Byte> state) {
			Span<UInt64> lann = MemoryMarshal.Cast<Byte, UInt64>(ann);
			ReadOnlySpan<UInt64> lstate = MemoryMarshal.Cast<Byte, UInt64>(state);
			int j = 0;
			for (int i = 0; i < 896 / 8 - 8; i++) lann[11 + i] ^= lstate[j++];
			for (int i = 0; i < 40 / 8; i++) lann[123 + i] ^= lstate[j++];
		}

		private static bool AnnMerkle__isItemValid(int depth, ReadOnlySpan<Byte> merkleBranch, ReadOnlySpan<Byte> itemHash, int itemNo) {
			Span<Byte> b = stackalloc Byte[2 * 64];
			itemHash.CopyTo(b.Slice((itemNo & 1) * 64, 64));
			for (int i = 0; i < depth; i++) {
				merkleBranch.Slice(i * 64, 64).CopyTo(b.Slice(((itemNo & 1) ^ 1) * 64, 64));
				itemNo >>= 1;
				Crypto.generichash_blake2b(b.Slice((itemNo & 1) * 64, 64), b);
			}
			return b.Slice((itemNo & 1) * 64, 64).SequenceEqual(merkleBranch.Slice(64 * depth, 64));
		}

		public static Boolean CheckContentProof(ReadOnlySpan<Byte> ann, UInt32 proofIdx, ReadOnlySpan<Byte> cpb) {
			var contentLength = GetContentLength(ann);
			var totalBlocks = contentLength / 32;
			if (totalBlocks * 32 < contentLength) totalBlocks++;
			var blockToProve = proofIdx % totalBlocks;
			var depth = Util_log2ceil(totalBlocks);
			Span<Byte> buf = new Byte[64];
			int offset = 0;
			var hash = cpb.Slice(offset, 32).ToArray();
			offset += 32;
			UInt32 blockSize = 32;
			for (int i = 0; i < depth; i++) {
				if (blockSize * (blockToProve ^ 1) >= contentLength) {
					blockToProve >>= 1;
					blockSize <<= 1;
					continue;
				}
				hash.CopyTo(buf.Slice((int)((blockToProve) & 1) * 32, 32));
				cpb.Slice(offset, 32).CopyTo(buf.Slice((int)((~blockToProve) & 1) * 32, 32));
				offset += 32;
				blockToProve >>= 1;
				blockSize <<= 1;
				Crypto.generichash_blake2b(hash, buf);
			}
			return ann.Slice(24, 32).SequenceEqual(hash);
		}

		private static void MkItem(uint itemNo, Span<Byte> item, ReadOnlySpan<Byte> seed) {
			const int announceItemHashcount = 1024 / 64;
			CryptoCycle.Hash_expand(item.Slice(0, 64), seed, itemNo);
			for (int i = 1; i < announceItemHashcount; i++) {
				Crypto.generichash_blake2b(item.Slice(64 * i, 64), item.Slice(64 * (i - 1), 64));
			}
			memocycle(item, announceItemHashcount, 2);
		}

		private static void memocycle(Span<Byte> item, int bufcount, int cycles) {
			Span<Byte> tmpbuf = new byte[128];
			for (int cycle = 0; cycle < cycles; cycle++) {
				for (int i = 0; i < bufcount; i++) {
					var p = (i - 1 + bufcount) % bufcount;
					int q = (int)(BitConverter.ToUInt32(item.Slice(64 * p, 4)) % (uint)(bufcount - 1));
					var j = (i + q) % bufcount;
					item.Slice(64 * p, 64).CopyTo(tmpbuf.Slice(0, 64));
					item.Slice(64 * j, 64).CopyTo(tmpbuf.Slice(64, 64));
					Crypto.generichash_blake2b(item.Slice(i * 64, 64), tmpbuf);
				}
			}
		}
	}
}

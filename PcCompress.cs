using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PacketCryptProof {
	internal class PcCompress_t {
		int branchHeight;
		int count;
		PcCompress_Entry_t[] entries;

		[StructLayout(LayoutKind.Sequential, Size = 32)]
		public struct Buf32_t {
			public UInt64 a, b, c, d;
		}

		public struct Entry_t {
			public Buf32_t hash;
			public UInt64 start;
			public UInt64 end;
		}

		public struct PcCompress_Entry_t {
			public UInt16 childLeft;
			public UInt16 childRight;
			public UInt16 parent;
			public UInt16 flags;
			public Entry_t e;
		}

		public static PcCompress_t PcCompress_mkEntryTable(UInt64 annCount, UInt64[] annNumbers) {
			const int PacketCrypt_NUM_ANNS = 4;
			for (int i = 0; i < PacketCrypt_NUM_ANNS; i++) if (annNumbers[i] >= annCount) return null;
			int branchHeight = CheckAnn.Util_log2ceil(annCount);
			UInt64 pathCount = pathForNum(annCount, branchHeight);
			UInt64[] annPaths = {
				pathForNum(annNumbers[0], branchHeight), pathForNum(annNumbers[1], branchHeight),
				pathForNum(annNumbers[2], branchHeight), pathForNum(annNumbers[3], branchHeight)
			};
			int capacity = branchHeight * PacketCrypt_NUM_ANNS * 3;
			PcCompress_t ret = new PcCompress_t();
			ret.entries = new PcCompress_Entry_t[capacity];
			ret.count = capacity;
			ret.branchHeight = branchHeight;
			UInt16 nextFree = 0;
			mkEntries(ret, annPaths, 0, 0, ref nextFree, UInt16.MaxValue, pathCount, annCount, 0);
			ret.count = nextFree;

			PcCompress_t out2 = PcCompress_mkEntryTable2(annCount, annNumbers);
			Debug.Assert(ret.count == out2.count);
			Debug.Assert(ret.branchHeight == out2.branchHeight);
			Debug.Assert(MemoryExtensions.SequenceEqual(new ReadOnlySpan<PcCompress_Entry_t>(ret.entries), new ReadOnlySpan<PcCompress_Entry_t>(out2.entries)));
			return out2;
		}

		private static PcCompress_t PcCompress_mkEntryTable2(UInt64 annCount, UInt64[] annNumbers) {
			const int PacketCrypt_NUM_ANNS = 4;
			for (int i = 0; i < PacketCrypt_NUM_ANNS; i++) {
				if (annNumbers[i] >= annCount) return null;
			}
			int branchHeight = CheckAnn.Util_log2ceil(annCount);
			int capacity = branchHeight * PacketCrypt_NUM_ANNS * 3;
			PcCompress_t ret = new PcCompress_t();
			ret.entries = new PcCompress_Entry_t[capacity];
			ret.count = capacity;
			ret.branchHeight = branchHeight;
			UInt16 nextFree = 0;
			if (mkEntries2(ret, annNumbers, 0, (ushort)branchHeight, UInt16.MaxValue, ref nextFree, annCount) != 0) {
				return null;
			}
			ret.count = nextFree;
			return ret;
		}

		private static UInt64 pathForNum(UInt64 num, int branchHeight) {
			return Util_reverse64(num) >> (64 - branchHeight);
		}

		private static UInt64 Util_reverse64(UInt64 x) {
			x = ((((x) >> (1)) & (0x5555555555555555ul)) | (((x) & (0x5555555555555555ul)) << (1)));
			x = ((((x) >> (2)) & (0x3333333333333333ul)) | (((x) & (0x3333333333333333ul)) << (2)));
			x = ((((x) >> (4)) & (0x0F0F0F0F0F0F0F0Ful)) | (((x) & (0x0F0F0F0F0F0F0F0Ful)) << (4)));
			return BinaryPrimitives.ReverseEndianness(x);
		}

		public const UInt16 PcCompress_F_COMPUTABLE = 1;
		public const UInt16 PcCompress_F_PAD_ENTRY = (1 << 1);
		public const UInt16 PcCompress_F_LEAF = (1 << 2);
		public const UInt16 PcCompress_F_RIGHT = (1 << 3);
		public const UInt16 PcCompress_F_PAD_SIBLING = (1 << 4);
		public const UInt16 PcCompress_F_FIRST_ENTRY = (1 << 5); // 0x20
		public const UInt16 PcCompress_F_HAS_HASH = (1 << 8);
		public const UInt16 PcCompress_F_HAS_RANGE = (1 << 9);
		public const UInt16 PcCompress_F_HAS_START = (1 << 10);

		private static void mkEntries(PcCompress_t tbl, UInt64[] annPaths, UInt64 bits, int depth, ref UInt16 nextFree, UInt16 parentNum, UInt64 pathCount, UInt64 annCount, UInt16 right) {
			UInt16 eNum = nextFree;
			Debug.Assert(eNum < tbl.count);
			nextFree = (ushort)(eNum + 1);
			ref PcCompress_Entry_t e = ref tbl.entries[eNum];
			e.parent = parentNum;

			UInt64 mask = (1ul << depth) - 1;
			for (int i = 0; i < 4; i++) {
				if (((annPaths[i] ^ bits) & mask) != 0) continue;
				// This entry is a parent of an announcement

				if (depth == tbl.branchHeight && bits == annPaths[i]) {
					// this entry IS an announcement
					e.childLeft = UInt16.MaxValue;
					e.childRight = UInt16.MaxValue;
					e.flags = (UInt16)(right | PcCompress_F_LEAF | PcCompress_F_COMPUTABLE);
					return;
				}
				Debug.Assert(depth != tbl.branchHeight);


				e.childLeft = nextFree;
				mkEntries(tbl, annPaths, bits, depth + 1, ref nextFree, eNum, pathCount, annCount, 0);
				e.childRight = nextFree;
				UInt64 nextBits = bits | (((UInt64)1) << depth);
				mkEntries(tbl, annPaths, nextBits, depth + 1, ref nextFree,
					eNum, pathCount, annCount, PcCompress_F_RIGHT);

				e.flags = (UInt16)(right | PcCompress_F_COMPUTABLE);
				if ((tbl.entries[e.childRight].flags & PcCompress_F_PAD_ENTRY) != 0) {
					tbl.entries[e.childLeft].flags |= PcCompress_F_PAD_SIBLING;
				}
				if ((bits & mask) == 0) {
					e.flags |= PcCompress_F_FIRST_ENTRY;
				}
				return;
			}

			// Not a parent of an announcement
			e.childLeft = UInt16.MaxValue;
			e.childRight = UInt16.MaxValue;

			if (pathForNum(bits, tbl.branchHeight) >= annCount) {
				Debug.Assert(right != 0);
				// It's a pad entry
				e.flags = (UInt16)(right | PcCompress_F_PAD_ENTRY | PcCompress_F_HAS_HASH | PcCompress_F_HAS_RANGE | PcCompress_F_HAS_START);
				if (depth == tbl.branchHeight) e.flags |= PcCompress_F_LEAF;
				MemoryMarshal.AsBytes(new Span<Entry_t>(ref e.e)).Fill(0xff);
				return;
			}

			// it's a sibling for which data must be provided
			e.flags = right;
			if (depth == tbl.branchHeight) {
				e.flags |= PcCompress_F_LEAF;
			}
			if ((bits & mask) == 0) {
				e.flags |= PcCompress_F_FIRST_ENTRY;
			}
			return;
		}

		private static int mkEntries2(PcCompress_t tbl, UInt64[] annNumbers, UInt64 bits, UInt16 iDepth, UInt16 parentNum, ref UInt16 nextFree, UInt64 annCount) {
			UInt16 eNum = nextFree;
			Debug.Assert(eNum < tbl.count);
			nextFree = (ushort)(eNum + 1);
			ref PcCompress_Entry_t e = ref tbl.entries[eNum];
			e.parent = parentNum;

			UInt64 mask = UInt64.MaxValue << iDepth;

			UInt16 flags = 0;
			flags |= ((bits >> iDepth) & 1) != 0 ? PcCompress_F_RIGHT : (UInt16)0;
			flags |= (iDepth == 0) ? PcCompress_F_LEAF : (UInt16)0;
			flags |= ((bits & mask) == 0) ? PcCompress_F_FIRST_ENTRY : (UInt16)0;

			for (int i = 0; i < 4; i++) {
				if (((annNumbers[i] ^ bits) & mask) != 0) continue;
				e.flags = (UInt16)(flags | PcCompress_F_COMPUTABLE);

				if ((flags & PcCompress_F_LEAF) != 0 && bits == annNumbers[i]) {
					// this entry IS an announcement
					e.childLeft = UInt16.MaxValue;
					e.childRight = UInt16.MaxValue;
					return 0;
				}
				Debug.Assert((flags & PcCompress_F_LEAF) == 0);

				e.childLeft = nextFree;
				Debug.Assert(mkEntries2(tbl, annNumbers, bits, (ushort)(iDepth - 1), eNum, ref nextFree, annCount) == 0);

				e.childRight = nextFree;
				UInt64 nextBits = bits | (((UInt64)1) << (iDepth - 1));
				Debug.Assert(mkEntries2(tbl, annNumbers, nextBits, (ushort)(iDepth - 1), eNum, ref nextFree, annCount) == 0);

				if ((tbl.entries[e.childRight].flags & PcCompress_F_PAD_ENTRY) != 0) {
					tbl.entries[e.childLeft].flags |= PcCompress_F_PAD_SIBLING;
				}
				return 0;
			}

			// Not the parent of any announcement
			e.childLeft = UInt16.MaxValue;
			e.childRight = UInt16.MaxValue;

			if (bits >= annCount) {
				// pad entry
				Debug.Assert((flags & PcCompress_F_RIGHT) != 0);
				e.flags = (UInt16)(flags | PcCompress_F_PAD_ENTRY | PcCompress_F_HAS_HASH | PcCompress_F_HAS_RANGE | PcCompress_F_HAS_START);
				MemoryMarshal.AsBytes(new Span<Entry_t>(ref e.e)).Fill(0xff);
				return 0;
			}

			// it's a sibling for which data must be provided
			e.flags = flags;
			return 0;
		}

		private static ref PcCompress_Entry_t getEntryByIndex(PcCompress_t tbl, UInt16 num) {
			Debug.Assert(num < tbl.count);
			return ref tbl.entries[num];
		}

		private static ref PcCompress_Entry_t PcCompress_getRoot(PcCompress_t tbl) {
			return ref getEntryByIndex(tbl, 0);
		}

		private static ref PcCompress_Entry_t PcCompress_getAnn(PcCompress_t tbl, UInt64 annNum) {
			UInt64 path = pathForNum(annNum, tbl.branchHeight);
			ref PcCompress_Entry_t e = ref PcCompress_getRoot(tbl);
			for (int i = 0; i < tbl.branchHeight; i++) {
				UInt16 next = (path & 1) != 0 ? e.childRight : e.childLeft;
				e = ref getEntryByIndex(tbl, next);
				path >>= 1;
			}
			//Debug.Assert((e.flags & PcCompress_F_LEAF) != 0); //PacketCrypt version, fails on block 24 and several others
			Debug.Assert((e.flags & (PcCompress_F_LEAF | PcCompress_F_COMPUTABLE)) != 0); //pktd version
			return ref e;
		}

		private static ref PcCompress_Entry_t PcCompress_getParent(PcCompress_t tbl, in PcCompress_Entry_t e) {
			if (e.parent >= tbl.count) {
				Debug.Assert(e.parent == UInt16.MaxValue);
				//Debug.Assert(e == tbl->entries);
				return ref Unsafe.NullRef<PcCompress_Entry_t>();
			}
			return ref getEntryByIndex(tbl, e.parent);
		}

		private static ref PcCompress_Entry_t PcCompress_getSibling(PcCompress_t tbl, in PcCompress_Entry_t e) {
			UInt16 num = (UInt16)Array.IndexOf(tbl.entries, e); // (e - tbl.entries);
			ref PcCompress_Entry_t p = ref PcCompress_getParent(tbl, e);
			if (Unsafe.IsNullRef(ref p)) return ref Unsafe.NullRef<PcCompress_Entry_t>();
			UInt16 sib = (p.childLeft == num) ? p.childRight : p.childLeft;
			Debug.Assert(((p.childLeft == num) ? 1 : (p.childRight == num ? 1 : 0)) != 0);
			return ref getEntryByIndex(tbl, sib);
		}

		private static bool PcCompress_hasExplicitRange(in PcCompress_Entry_t e) {
			// right leaf needs an explicit range provided at the beginning
			if ((e.flags & (PcCompress_F_LEAF | PcCompress_F_RIGHT | PcCompress_F_PAD_ENTRY)) == (PcCompress_F_LEAF | PcCompress_F_RIGHT)) {
				return true;
			}

			// anything that is not a LEAF
			// not a COMPUTABLE
			// not a PAD_ENTRY nor a sibling of one
			return 0 == (e.flags & (PcCompress_F_LEAF | PcCompress_F_COMPUTABLE | PcCompress_F_PAD_ENTRY | PcCompress_F_PAD_SIBLING));
		}

		private static bool PcCompress_HAS_ALL(UInt16 x, UInt16 flags) {
			return (((x) & (flags)) == (flags));
		}

		private static Boolean IS_FFFF(ref Entry_t x) {
			//_Static_assert(Buf_SIZEOF(x) <= 48, ""); \
			//!memcmp((x), FFFF, Buf_SIZEOF(x)); \
			return !MemoryExtensions.ContainsAnyExcept(MemoryMarshal.AsBytes(new ReadOnlySpan<Entry_t>(ref x)), (Byte)0xFF);
		}

		public static int PacketCryptProof_hashProof(Span<Byte> hashOut, Span<Byte> annHashes, UInt64 totalAnns, ReadOnlySpan<UInt64> annIndexes, ReadOnlySpan<Byte> cpcp) {
			// We need to bump the numbers to account for the zero entry
			UInt64[] annIdxs = new ulong[4];
			for (int i = 0; i < 4; i++) annIdxs[i] = (annIndexes[i] % totalAnns) + 1;
			totalAnns++;

			PcCompress_t tbl = PcCompress_mkEntryTable(totalAnns, annIdxs);

			// fill in announcement hashes
			for (int i = 0; i < 4; i++) {
				ref PcCompress_Entry_t e = ref PcCompress_getAnn(tbl, annIdxs[i]);
				annHashes.Slice(i * 32, 32).CopyTo(MemoryMarshal.AsBytes(new Span<Buf32_t>(ref e.e.hash)));
				e.flags |= PcCompress_t.PcCompress_F_HAS_HASH;
			}

			int cpoffset = 0;
			// Fill in the hashes and ranges which are provided
			for (int i = 0; i < tbl.count; i++) {
				ref PcCompress_Entry_t e = ref tbl.entries[i];
				if (PcCompress_hasExplicitRange(e)) {
					e.e.end = BitConverter.ToUInt64(cpcp.Slice(cpoffset, 8));
					cpoffset += 8;
					e.flags |= PcCompress_F_HAS_RANGE;
				}
				if (0 == (e.flags & (PcCompress_F_HAS_HASH | PcCompress_t.PcCompress_F_COMPUTABLE))) {
					cpcp.Slice(cpoffset, 32).CopyTo(MemoryMarshal.AsBytes(new Span<Buf32_t>(ref e.e.hash)));
					cpoffset += 32;
					e.flags |= PcCompress_F_HAS_HASH;
				}
			}
			Debug.Assert(cpoffset == cpcp.Length);

			// Calculate the start and end for each of the announcements and their siblings
			// We treat leaf siblings specially because right leafs have no explicit range
			for (int i = 0; i < 4; i++) {
				ref PcCompress_Entry_t e = ref PcCompress_getAnn(tbl, annIdxs[i]);
				Debug.Assert(PcCompress_HAS_ALL(e.flags, (PcCompress_F_HAS_HASH | PcCompress_F_LEAF)));

				// same announcement used in two proofs OR two of the announcements are neighbors
				if ((e.flags & PcCompress_F_HAS_START) != 0) continue; 

				ref PcCompress_Entry_t sib = ref PcCompress_getSibling(tbl, e);

				if (PcCompress_HAS_ALL(sib.flags, (PcCompress_F_PAD_ENTRY | PcCompress_F_HAS_START))) {
					// revert this back to a range to simplify code below
					sib.e.end = 0;
					sib.flags &= unchecked((UInt16)(~PcCompress_F_HAS_START));
				}

				Debug.Assert(PcCompress_HAS_ALL(sib.flags, (PcCompress_F_HAS_HASH | PcCompress_F_LEAF)));
				Debug.Assert((sib.flags & PcCompress_F_HAS_START) == 0);

				e.e.start = e.e.hash.a;
				sib.e.start = sib.e.hash.a;
				if ((e.flags & PcCompress_F_RIGHT) != 0) {
					e.e.end += e.e.start;
					sib.e.end = e.e.start;
				} else {
					e.e.end = sib.e.start;
					sib.e.end += sib.e.start;
				}
				Debug.Assert(e.e.end > e.e.start);
				e.flags |= PcCompress_F_HAS_START | PcCompress_F_HAS_RANGE;
				sib.flags |= PcCompress_F_HAS_START | PcCompress_F_HAS_RANGE;
			}

			// for each announcement, walk up the tree computing as far back as possible
			// at the last announcement, we must reach the root.
			for (int i = 0; i < 4; i++) {
				ref PcCompress_Entry_t e = ref PcCompress_getAnn(tbl, annIdxs[i]);
				Debug.Assert(PcCompress_HAS_ALL(e.flags, (PcCompress_F_HAS_HASH | PcCompress_F_HAS_RANGE | PcCompress_F_HAS_START)));
				for (; ; ) {
					ref PcCompress_Entry_t parent = ref PcCompress_getParent(tbl, e);

					// hit the root, this means we're done.
					// i may not be equal to PacketCrypt_NUM_ANNS-1 if there is a duplicate announcement
					if (Unsafe.IsNullRef(ref parent)) break;

					// Parent has already been computed, dupe or neighboring anns
					if ((parent.flags & PcCompress_F_HAS_HASH) != 0) break;

					ref PcCompress_Entry_t sib = ref PcCompress_getSibling(tbl, e);
					Debug.Assert(!Unsafe.IsNullRef(ref sib));

					// We can't compute any further because we need to compute the other
					// sibling in order to continue. When we get to the last announcement,
					// that will hash up the whole way.
					if (0 == (sib.flags & PcCompress_F_HAS_HASH)) break;

					// assertions
					Debug.Assert((parent.flags & PcCompress_F_COMPUTABLE) != 0);
					Debug.Assert((parent.flags & (PcCompress_F_HAS_HASH | PcCompress_F_HAS_RANGE | PcCompress_F_HAS_START)) == 0);
					bool eIsRight = 0 != (e.flags & PcCompress_F_RIGHT);

					if (0 == (sib.flags & PcCompress_F_HAS_RANGE)) {
						Debug.Assert(0 == (sib.flags & PcCompress_F_PAD_SIBLING) || eIsRight);
						sib.e.end = UInt64.MaxValue - e.e.end;
						sib.flags |= PcCompress_F_HAS_RANGE;
					}

					Debug.Assert(PcCompress_HAS_ALL(sib.flags, (PcCompress_F_HAS_HASH | PcCompress_F_HAS_RANGE)));

					if (0 == (sib.flags & PcCompress_F_HAS_START)) {
						if (eIsRight) {
							// left.start = right.start - left.range
							sib.e.start = e.e.start - sib.e.end;
							// left.end = right.start
							sib.e.end = e.e.start;
						} else {
							// right.start = left.end
							sib.e.start = e.e.end;
							// right.end = right.range + right.start
							sib.e.end += sib.e.start;
						}
						sib.flags |= PcCompress_F_HAS_START;

						// No sum of ranges can be greater than UINT_MAX or less than 1
						Debug.Assert(sib.e.end > sib.e.start);
					}
					Entry_t[] buf = new Entry_t[2];
					buf[eIsRight ? 1 : 0] = e.e;
					buf[eIsRight ? 0 : 1] = sib.e;

					// the sum of ranges between two announcement hashes must equal
					// the difference between the hash values
					Debug.Assert(buf[1].start == buf[0].end);

					Debug.Assert(buf[1].end > buf[1].start || IS_FFFF(ref buf[1]));
					Debug.Assert(buf[0].end > buf[0].start || IS_FFFF(ref buf[0]));

					Crypto.generichash_blake2b(MemoryMarshal.AsBytes(new Span<Buf32_t>(ref parent.e.hash)), MemoryMarshal.AsBytes(new Span<Entry_t>(buf)));
					parent.e.start = buf[0].start;
					parent.e.end = buf[1].end;
					parent.flags |= (PcCompress_F_HAS_HASH | PcCompress_F_HAS_RANGE | PcCompress_F_HAS_START);
					e = parent;
				}
			}

			ref PcCompress_Entry_t root = ref PcCompress_getRoot(tbl);

			Debug.Assert((root.flags == (PcCompress_F_HAS_START | PcCompress_F_HAS_HASH | PcCompress_F_HAS_RANGE | PcCompress_F_COMPUTABLE | PcCompress_F_FIRST_ENTRY)));
			Debug.Assert(root.e.start == 0 && root.e.end == UInt64.MaxValue);

			Crypto.generichash_blake2b(hashOut, MemoryMarshal.AsBytes(new ReadOnlySpan<Entry_t>(ref root.e)));
			return 0;
		}
	}
}

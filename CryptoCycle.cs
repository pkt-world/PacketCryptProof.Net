using System.Runtime.InteropServices;

namespace PacketCryptProof {
	public static class CryptoCycle {
		public static void Initialize(Span<Byte> state, ReadOnlySpan<Byte> seed, UInt64 nonce) {
			if (state.Length != 2048) throw new ArgumentException("state");
			Hash_expand(state, seed, 0);
			MemoryMarshal.Write(state.Slice(0, 8), nonce);
			MakeFuzzable(state);
		}

		internal static void Hash_expand(Span<Byte> buff, ReadOnlySpan<Byte> seed, UInt32 num) {
			Span<UInt32> nonce = stackalloc UInt32[3];
			nonce[0] = num;
			nonce[1] = 0x455F4350; //PC_E
			nonce[2] = 0x444E5058; //XPND
			Crypto.stream_chacha20_ietf(buff, MemoryMarshal.AsBytes(nonce), seed);
		}

		public static void MakeFuzzable(Span<Byte> state) {
			UInt32 data = MemoryMarshal.Read<UInt32>(state.Slice(16, 4));
			data = (data & 0x00FFFFFF) | (32 << 17);
			MemoryMarshal.Write(state.Slice(12, 4), data);
		}

		public static void Update(Span<Byte> state, ReadOnlySpan<Byte> item, ReadOnlySpan<Byte> contentBlock) {
			if (state.Length != 2048) throw new ArgumentException("state");
			if (item.Length != 1024) throw new ArgumentException("item");
			item.CopyTo(state.Slice(2 * 16, 1024));
			if (contentBlock != null) contentBlock.CopyTo(state.Slice(32 + 1024));
			MakeFuzzable(state);
			Crypt(state);
		}

		public static void ScalarMult(Span<Byte> state) {
			if (state.Length != 2048) throw new ArgumentException("state");
			Span<Byte> pubkey = stackalloc Byte[32];
			Crypto.scalarmult_curve25519_base(pubkey, state.Slice(32 * 1, 32));
			Crypto.scalarmult_curve25519(state.Slice(32 * 2, 32), state.Slice(32 * 0, 32), pubkey);
		}

		public static void Finalize(Span<Byte> state) {
			if (state.Length != 2048) throw new ArgumentException("state");
			Crypto.generichash_blake2b(state.Slice(0, 32), state);
		}

		public static UInt64 GetItemNumber(ReadOnlySpan<Byte> state) {
			return BitConverter.ToUInt64(state.Slice(16 * 1, 8));
		}

		public static void Crypt(Span<Byte> msg) {
			Span<Byte> state = stackalloc Byte[256];
			{
				Span<Byte> block0 = stackalloc Byte[64];
				block0.Clear();
				Crypto.stream_chacha20_ietf(block0, msg.Slice(0, 12), msg.Slice(16, 32));
				Crypto.onetimeauth_poly1305_init(state, block0);
			}

			Span<Byte> aead = msg.Slice(48);
			int aeadLen = (int)CryptoCycle_getAddLen(msg) * 16;
			int msgLen = (int)getLengthAndTruncate(msg) * 16;
			uint tzc = CryptoCycle_getTrailingZeros(msg);
			uint azc = CryptoCycle_getAdditionalZeros(msg);
			Span<Byte> msgContent = aead.Slice(aeadLen);
			Crypto.onetimeauth_poly1305_update(state, aead.Slice(0, aeadLen));

			Boolean decrypt = CryptoCycle_isDecrypt(msg);
			if (decrypt) Crypto.onetimeauth_poly1305_update(state, msgContent.Slice(0, msgLen));

			Crypto.stream_chacha20_ietf_xor_ic(msgContent, msgContent.Slice(0, msgLen), msg.Slice(0, 12), 1, msg.Slice(16, 32));

			if (!decrypt) {
				if (tzc != 0) msgContent.Slice((int)(msgLen - tzc), (int)tzc).Clear();
				Crypto.onetimeauth_poly1305_update(state, msgContent.Slice(0, msgLen));
			}

			{
				Span<UInt64> slen = stackalloc UInt64[2];
				slen[0] = ((UInt64)aeadLen) - azc;
				slen[1] = ((UInt64)msgLen) - tzc;
				Crypto.onetimeauth_poly1305_update(state, MemoryMarshal.AsBytes(slen));
			}
			Crypto.onetimeauth_poly1305_final(state, msg.Slice(16, 16));
		}

		private static UInt32 CryptoCycle_getBits(ReadOnlySpan<Byte> hdr, int begin, int count) {
			UInt32 data = BitConverter.ToUInt32(hdr.Slice(12, 4));
			return (data >> begin) & ((1u << count) - 1);
		}

		private static void CryptoCycle_setBits(Span<Byte> hdr, int begin, int count, UInt32 val) {
			val &= (1u << count) - 1;
			UInt32 data = MemoryMarshal.Read<UInt32>(hdr.Slice(12, 4));
			data = (data & (~(((1u << count) - 1) << begin))) | ((val) << begin);
			MemoryMarshal.Write(hdr.Slice(12, 4), data);
		}

		private static UInt32 CryptoCycle_getAddLen(ReadOnlySpan<Byte> hdr) {
			return CryptoCycle_getBits(hdr, 13, 3);
		}

		private static UInt32 CryptoCycle_getLength(ReadOnlySpan<Byte> hdr) {
			return CryptoCycle_getBits(hdr, 17, 7);
		}

		private static void CryptoCycle_setTruncated(Span<Byte> hdr, Boolean value) {
			CryptoCycle_setBits(hdr, 16, 1, value ? 1u : 0);
		}

		private static void CryptoCycle_setLength(Span<Byte> hdr, UInt32 value) {
			CryptoCycle_setBits(hdr, 17, 7, value);
		}

		private static UInt32 getLengthAndTruncate(Span<Byte> hdr) {
			uint len = CryptoCycle_getLength(hdr);
			uint maxLen = 125 - CryptoCycle_getAddLen(hdr);
			uint finalLen = (len > maxLen) ? maxLen : len;
			CryptoCycle_setTruncated(hdr, (finalLen != len));
			CryptoCycle_setLength(hdr, finalLen);
			return finalLen;

		}

		private static UInt32 CryptoCycle_getTrailingZeros(ReadOnlySpan<Byte> hdr) {
			return CryptoCycle_getBits(hdr, 8, 4);
		}

		private static UInt32 CryptoCycle_getAdditionalZeros(ReadOnlySpan<Byte> hdr) {
			return CryptoCycle_getBits(hdr, 0, 4);
		}

		private static Boolean CryptoCycle_isDecrypt(ReadOnlySpan<Byte> hdr) {
			return CryptoCycle_getBits(hdr, 12, 1) != 0;
		}
	}
}

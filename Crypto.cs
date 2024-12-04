using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PacketCryptProof {
	public static partial class Crypto {
		const String SODIUM_LIB = "libsodium";
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_generichash_blake2b(Span<Byte> @out, nuint outlen, ReadOnlySpan<Byte> @in, UInt64 inlen, IntPtr key, nint keylen);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_stream_chacha20_ietf_xor_ic(Span<Byte> c, ReadOnlySpan<Byte> m, UInt64 mlen, ReadOnlySpan<Byte> n, UInt32 ic, ReadOnlySpan<Byte> k);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_scalarmult_curve25519_base(Span<Byte> q, ReadOnlySpan<Byte> n);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_scalarmult_curve25519(Span<Byte> q, ReadOnlySpan<Byte> n, ReadOnlySpan<Byte> p);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_stream_chacha20_ietf(Span<Byte> c, UInt64 clen, ReadOnlySpan<Byte> n, ReadOnlySpan<Byte> k);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_onetimeauth_poly1305_init(Span<Byte> state, ReadOnlySpan<Byte> key);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_onetimeauth_poly1305_update(Span<Byte> state, ReadOnlySpan<Byte> @in, UInt64 inlen);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_onetimeauth_poly1305_final(Span<Byte> state, Span<Byte> @out);
		[LibraryImport(SODIUM_LIB)]
		private static partial int crypto_sign_ed25519_verify_detached(ReadOnlySpan<Byte> sig, ReadOnlySpan<Byte> m, UInt64 mlen, ReadOnlySpan<Byte> pk);

		public static void generichash_blake2b(Span<Byte> @out, ReadOnlySpan<Byte> @in) {
			int ret = crypto_generichash_blake2b(@out, checked((nuint)@out.Length), @in, checked((UInt64)@in.Length), IntPtr.Zero, 0);
			if (ret != 0) throw new ArgumentException();
		}
		public static void stream_chacha20_ietf_xor_ic(Span<Byte> c, ReadOnlySpan<Byte> m, ReadOnlySpan<Byte> n, UInt32 ic, ReadOnlySpan<Byte> k) {
			if (c.Length < m.Length) throw new ArgumentOutOfRangeException("c");
			if (n.Length < 8) throw new ArgumentOutOfRangeException("n");
			if (k.Length < 32) throw new ArgumentOutOfRangeException("k");
			int ret = crypto_stream_chacha20_ietf_xor_ic(c, m, checked((UInt64)m.Length), n, ic, k);
			if (ret != 0) throw new ArgumentException();
		}
		public static void stream_chacha20_ietf(Span<Byte> c, ReadOnlySpan<Byte> n, ReadOnlySpan<Byte> k) {
			if (c.Length < 64) throw new ArgumentOutOfRangeException("c");
			if (n.Length < 8) throw new ArgumentOutOfRangeException("n");
			if (k.Length < 32) throw new ArgumentOutOfRangeException("k");
			int ret = crypto_stream_chacha20_ietf(c, checked((UInt64)c.Length), n, k);
			if (ret != 0) throw new ArgumentException();
		}
		public static void scalarmult_curve25519_base(Span<Byte> q, ReadOnlySpan<Byte> n) {
			if (q.Length < 32) throw new ArgumentOutOfRangeException("q");
			if (n.Length < 32) throw new ArgumentOutOfRangeException("n");
			int ret = crypto_scalarmult_curve25519_base(q, n);
			if (ret != 0) throw new ArgumentException();
		}
		public static void scalarmult_curve25519(Span<Byte> q, ReadOnlySpan<Byte> n, ReadOnlySpan<Byte> p) {
			if (q.Length < 32) throw new ArgumentOutOfRangeException("q");
			if (n.Length < 32) throw new ArgumentOutOfRangeException("n");
			if (p.Length < 32) throw new ArgumentOutOfRangeException("p");
			int ret = crypto_scalarmult_curve25519(q, n, p);
			if (ret != 0) throw new ArgumentException();
		}
		public static void onetimeauth_poly1305_init(Span<Byte> state, ReadOnlySpan<Byte> key) {
			if (state.Length < 256) throw new ArgumentOutOfRangeException("state");
			if (key.Length < 32) throw new ArgumentOutOfRangeException("key");
			int ret = crypto_onetimeauth_poly1305_init(state, key);
			if (ret != 0) throw new ArgumentException();
		}
		public static void onetimeauth_poly1305_update(Span<Byte> state, ReadOnlySpan<Byte> @in) {
			if (state.Length < 256) throw new ArgumentOutOfRangeException("state");
			int ret = crypto_onetimeauth_poly1305_update(state, @in, checked((UInt64)@in.Length));
			if (ret != 0) throw new ArgumentException();
		}
		public static void onetimeauth_poly1305_final(Span<Byte> state, Span<Byte> @out) {
			if (state.Length < 256) throw new ArgumentOutOfRangeException("state");
			if (@out.Length < 16) throw new ArgumentOutOfRangeException("state");
			int ret = crypto_onetimeauth_poly1305_final(state, @out);
			if (ret != 0) throw new ArgumentException();
		}

		public static Boolean sign_ed25519_verify(ReadOnlySpan<Byte> sig, ReadOnlySpan<Byte> m, ReadOnlySpan<Byte> pk) {
			if (sig.Length < 64) throw new ArgumentOutOfRangeException("sig");
			if (pk.Length < 32) throw new ArgumentOutOfRangeException("pk");
			return crypto_sign_ed25519_verify_detached(sig, m, checked((ulong)m.Length), pk) == 0;
		}
	}
}

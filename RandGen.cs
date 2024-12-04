using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PacketCryptProof {
	internal static partial class RandGen {
		class Context {
			// Random generator
			public Byte[] randseed = new byte[32];
			public Byte[] randbuf = new byte[64];
			public UInt32 nextInt;
			public UInt32 ctr;

			// output
			public List<UInt32> insns = new List<uint>();

			// variables / scopes
			public List<UInt32> vars = new List<uint>();
			public UInt32 scope;

			public bool tooBig;
		}

		const int Conf_RandGen_INITIAL_BUDGET = 20000;
		const int Conf_RandGen_MAX_INSNS = 2048;
		const int Conf_RandGen_LOOP_MIN_CYCLES = 2;
		const int Conf_RandGen_MEMORY_COST = 20;
		const int Conf_RandGen_INPUT_COST = 2;
		const int Conf_RandGen_BRANCH_COST = 50;
		const int Conf_RandGen_RANDOM_BRANCH_LIKELYHOOD = 2;
		const int Conf_RandGen_IMMEDIATE_LIKELYHOOD = 4;
		const int Conf_RandGen_VAR_REUSE_LIKELYHOOD = 8;
		const int Conf_RandGen_HIGHER_SCOPE_LIKELYHOOD = 4;

		[LibraryImport("packetcrypt.dll")]
		private static partial int RandGen_generate(Span<UInt32> buf, ReadOnlySpan<Byte> seed);

		public static UInt32[] Generate(Span<Byte> seed) {
			UInt32[] insns = new uint[Conf_RandGen_MAX_INSNS];
			int len = RandGen_generate(insns, seed);
			Array.Resize(ref insns, len);

			UInt32 budget = Conf_RandGen_INITIAL_BUDGET;
			Context ctx = new Context();
			seed.CopyTo(ctx.randseed);
			ctx.nextInt = UInt32.MaxValue;

			loop(ctx, ref budget);

			if (ctx.tooBig) return null;

			Debug.Assert(MemoryExtensions.SequenceEqual<UInt32>(insns, ctx.insns.ToArray()));

			return ctx.insns.ToArray();
		}

		private static int loop(Context ctx, ref UInt32 budget) {
			UInt32 loopLen = randRange(ctx, Conf_RandGen_LOOP_MIN_CYCLES, Conf_RandGen_LOOP_MAX_CYCLES(ctx.scope));
			// this must be at least 2
			uint numMemAcc = randRange(ctx, 2, 4);

			if (budget < (Conf_RandGen_MEMORY_COST * loopLen)) return 0;
			budget /= loopLen;
			emit(ctx, (loopLen << 20) | (Byte)RHOpCodes.OpCode_LOOP);
			scope(ctx);

			UInt32 memTemplate = (randu32(ctx) << 8) | (Byte)RHOpCodes.OpCode_MEMORY;
			for (int i = 0; i < numMemAcc; i++) {
				if (!spend(ref budget, Conf_RandGen_MEMORY_COST)) { break; }
				mkVar(ctx);
				emit(ctx, DecodeInsn_MEMORY_WITH_CARRY(memTemplate, randu32(ctx)));
			}
			int ret = body(ctx, ref budget, false);
			end(ctx);
			return ret;
		}

		private static uint Conf_RandGen_LOOP_MAX_CYCLES(uint scopeDepth) {
			return 7 + scopeDepth * 29;
		}

		private static uint randRange(Context ctx, uint start, uint end) {
			return randu32(ctx) % (end - start) + start;
		}

		private static UInt32 randu32(Context ctx) {
			if (ctx.nextInt >= ctx.randbuf.Length / 4) {
				CryptoCycle.Hash_expand(ctx.randbuf, ctx.randseed, ctx.ctr++);
				ctx.nextInt = 0;
			}
			return BitConverter.ToUInt32(ctx.randbuf, 4 * (int)(ctx.nextInt++));
		}

		private static void emit(Context ctx, UInt32 insn) {
			if (ctx.insns.Count >= Conf_RandGen_MAX_INSNS) {
				ctx.tooBig = true;
				return;
			}
			ctx.insns.Add(insn);
		}

		private static void scope(Context ctx) {
			ctx.scope++;
			ctx.vars.Add(~0u);
		}

		private static bool spend(ref UInt32 budget, UInt32 amount) {
			if (budget >= amount) {
				budget -= amount;
				return true;
			}
			return false;
		}

		private static void mkVar(Context ctx) {
			ctx.vars.Add(0);
		}

		private static UInt32 DecodeInsn_MEMORY_WITH_CARRY(UInt32 insn, uint carry) {
			return (((insn) & ~(15u << 9)) | (((carry) & 15) << 9));
		}

		private static int body(Context ctx, ref UInt32 budget, bool createScope) {
			if (createScope) { scope(ctx); }
			for (; ; ) {
				if (ctx.insns.Count > Conf_RandGen_MAX_INSNS) goto @out;
				uint max = randRange(ctx, 2, 12);
				for (uint i = 1; i <= max; i++) {
					if (cointoss(ctx, 4 * max / i) && op(ctx, OpType.OpType_4_4, ref budget)) { continue; }
					if (cointoss(ctx, 3 * max / i) && op(ctx, OpType.OpType_4_2, ref budget)) { continue; }
					if (cointoss(ctx, 3 * max / i) && op(ctx, OpType.OpType_2_2, ref budget)) { continue; }
					if (cointoss(ctx, 2 * max / i) && op(ctx, OpType.OpType_2_1, ref budget)) { continue; }
					if (cointoss(ctx, 1 * i) && input(ctx, ref budget)) { continue; }
					if (op(ctx, OpType.OpType_1_1, ref budget)) { continue; }
					goto @out;
				}
				if (Conf_RandGen_SHOULD_BRANCH(randu32(ctx), ctx.insns.Count) && branch(ctx, ref budget) == 0) goto @out;
				if (Conf_RandGen_SHOULD_LOOP(randu32(ctx)) && loop(ctx, ref budget) == 0) goto @out;
			}
			@out:
			if (createScope) end(ctx);
			return 0;
		}

		private static T Pop<T>(this List<T> list) {
			int index = list.Count - 1;
			T value = list[index];
			list.RemoveAt(index);
			return value;
		}


		private static void end(Context ctx) {
			emit(ctx, (Byte)RHOpCodes.OpCode_END);
			ctx.scope--;
			while (ctx.vars.Pop() != ~0u) ;
		}

		private static Boolean cointoss(Context ctx, UInt32 oneIn) {
			return (randu32(ctx) % oneIn) == 0;
		}

		enum OpType : int {
			OpType_1_1 = 0,
			OpType_2_1 = 1,
			OpType_2_2 = 2,
			OpType_4_2 = 3,
			OpType_4_4 = 4
		};

		static uint[] COST_BY_TYPE = { 1, 2, 4, 8, 16 };

		private static bool op(Context ctx, OpType type, ref UInt32 budget) {
			UInt32 rand = randu32(ctx);
			if (!spend(ref budget, COST_BY_TYPE[(int)type])) { return false; }
			switch (type) {
				case OpType.OpType_1_1: {
						emit(ctx, GET_OP(CODES_1_1, rand) | getA(ctx, false));
						mkVar(ctx);
						break;
					}
				case OpType.OpType_2_1: {
						emit(ctx, GET_OP(CODES_2_1, rand) | getA(ctx, false) | getB(ctx, false));
						mkVar(ctx);
						break;
					}

				case OpType.OpType_2_2: {
						emit(ctx, GET_OP(CODES_2_2, rand) | getA(ctx, false) | getB(ctx, false));
						mkVar(ctx); mkVar(ctx);
						break;
					}
				case OpType.OpType_4_2: {
						emit(ctx, GET_OP(CODES_4_2, rand) | getA(ctx, true) | getB(ctx, true));
						mkVar(ctx); mkVar(ctx);
						break;
					}
				case OpType.OpType_4_4: {
						emit(ctx, GET_OP(CODES_4_4, rand) | getA(ctx, true) | getB(ctx, true));
						mkVar(ctx); mkVar(ctx); mkVar(ctx); mkVar(ctx);
						break;
					}
			}
			return true;
		}

		private static bool input(Context ctx, ref UInt32 budget) {
			if (!spend(ref budget, Conf_RandGen_INPUT_COST)) { return false; }
			mkVar(ctx);
			emit(ctx, (randu32(ctx) << 8) | (Byte)RHOpCodes.OpCode_IN);
			return true;
		}

		private static Boolean Conf_RandGen_SHOULD_LOOP(UInt32 rand) {
			return (((rand) % 32) < 23);
		}

		private static Boolean Conf_RandGen_SHOULD_BRANCH(UInt32 rand, int insnCount) {
			return (((rand) % 64 + (insnCount * 25 / Conf_RandGen_MAX_INSNS)) < 50);
		}

		private static int branch(Context ctx, ref UInt32 budget) {
			if (!spend(ref budget, Conf_RandGen_BRANCH_COST)) return 0;
			UInt32 op = cointoss(ctx, Conf_RandGen_RANDOM_BRANCH_LIKELYHOOD) ? (Byte)RHOpCodes.OpCode_IF_RANDOM : (Byte)RHOpCodes.OpCode_IF_LIKELY;

			emit(ctx, getA(ctx, false) | op | (2 << 20));
			UInt32 j1 = (UInt32)ctx.insns.Count;
			emit(ctx, (Byte)RHOpCodes.OpCode_JMP);

			UInt32 b1 = Conf_RandGen_IF_BODY_BUDGET(budget, ctx.scope);
			body(ctx, ref b1, true);

			UInt32 j2 = (UInt32)ctx.insns.Count;
			emit(ctx, (Byte)RHOpCodes.OpCode_JMP);

			UInt32 b2 = Conf_RandGen_IF_BODY_BUDGET(budget, ctx.scope);
			body(ctx, ref b2, true);

			// Now we fill in the first jmp
			ctx.insns[(int)j1] = ((j2 - j1) << 8) | (Byte)RHOpCodes.OpCode_JMP;

			// and then the else jmp
			ctx.insns[(int)j2] = (((uint)ctx.insns.Count - j2 - 1) << 8) | (Byte)RHOpCodes.OpCode_JMP;
			return 1;
		}

		private static UInt32 Conf_RandGen_IF_BODY_BUDGET(UInt32 budget, UInt32 scopes) {
			return (((budget) * 7) / 32);
		}

		private static int _getVar(Context ctx, bool dbl) {
			int eof = ctx.vars.Count;
			int bof = eof - 1;
			for (; bof >= 0; bof--) {
				if (ctx.vars[bof] != ~0u) { continue; }
				// only 1 var in this frame and we're looking for dword, continue looking
				if (dbl) {
					if (bof >= eof - 2) { goto nextFrame; }
				} else {
					// no vars in this frame, continue looking
					if (bof >= eof - 1) { goto nextFrame; }
				}
				// end of the line, this is tested after because first frame should always have 4 vars.
				if (bof == 0) break;
				// walk up to a higher scope
				if (!cointoss(ctx, Conf_RandGen_HIGHER_SCOPE_LIKELYHOOD)) break;
			nextFrame:
				eof = bof;
			}
			int start = (int)randRange(ctx, (uint)bof + 1, (uint)eof);
			//printf("%d %d %d - %d\n", bof, eof, start, dbl);
			for (int j = start + 1; ; j++) {
				if (j >= eof) { j = bof + 1; }
				//printf("%08x %d\n", ctx->vars.elems[j], j);
				if ((!dbl || (j > bof + 1)) && cointoss(ctx, Conf_RandGen_VAR_REUSE_LIKELYHOOD)) {
					//printf("reuse\n");
					return j;
				} else if (0 == (ctx.vars[j] & 1)) {
					if (!dbl || 0 == (ctx.vars[j - 1] & 1)) { return j; }
				}
			}
		}

		private static int getVar(Context ctx, bool dbl) {
			int @out = _getVar(ctx, dbl);
			ctx.vars[@out] |= 1;
			if (dbl) {
				ctx.vars[@out - 1] |= 1;
			}
			return @out;
		}

		private static UInt32 getA(Context ctx, bool dbl) {
			return ((UInt32)getVar(ctx, dbl)) << 9;
		}

		private static UInt32 getB(Context ctx, bool dbl) {
			if (cointoss(ctx, Conf_RandGen_IMMEDIATE_LIKELYHOOD)) {
				return (randu32(ctx) << 20) | (1 << 18);
			} else {
				return ((UInt32)getVar(ctx, dbl)) << 20;
			}
		}

		private static UInt32 GET_OP(RHOpCodes[] list, uint idx) {
			return (Byte)list[idx % list.Length];
		}

		private static RHOpCodes[] CODES_1_1 = {
			RHOpCodes.OpCode_POPCNT8, RHOpCodes.OpCode_POPCNT16, RHOpCodes.OpCode_POPCNT32,
			RHOpCodes.OpCode_CLZ8, RHOpCodes.OpCode_CLZ16, RHOpCodes.OpCode_CLZ32,
			RHOpCodes.OpCode_CTZ8, RHOpCodes.OpCode_CTZ16, RHOpCodes.OpCode_CTZ32,
			RHOpCodes.OpCode_BSWAP16, RHOpCodes.OpCode_BSWAP32,
		};

		private static RHOpCodes[] CODES_2_1 = {
			RHOpCodes.OpCode_ADD8, RHOpCodes.OpCode_ADD16, RHOpCodes.OpCode_ADD32,
			RHOpCodes.OpCode_SUB8, RHOpCodes.OpCode_SUB16, RHOpCodes.OpCode_SUB32,
			RHOpCodes.OpCode_SHLL8, RHOpCodes.OpCode_SHLL16, RHOpCodes.OpCode_SHLL32,
			RHOpCodes.OpCode_SHRL8, RHOpCodes.OpCode_SHRL16, RHOpCodes.OpCode_SHRL32,
			RHOpCodes.OpCode_SHRA8, RHOpCodes.OpCode_SHRA16, RHOpCodes.OpCode_SHRA32,
			RHOpCodes.OpCode_ROTL8, RHOpCodes.OpCode_ROTL16, RHOpCodes.OpCode_ROTL32,
			RHOpCodes.OpCode_MUL8, RHOpCodes.OpCode_MUL16, RHOpCodes.OpCode_MUL32,
			RHOpCodes.OpCode_AND,
			RHOpCodes.OpCode_OR,
			RHOpCodes.OpCode_XOR,
		};

		private static RHOpCodes[] CODES_2_2 = {
			RHOpCodes.OpCode_ADD8C, RHOpCodes.OpCode_ADD16C, RHOpCodes.OpCode_ADD32C,
			RHOpCodes.OpCode_SUB8C, RHOpCodes.OpCode_SUB16C, RHOpCodes.OpCode_SUB32C,
			RHOpCodes.OpCode_MUL8C, RHOpCodes.OpCode_MUL16C, RHOpCodes.OpCode_MUL32C,
			RHOpCodes.OpCode_MULSU8C, RHOpCodes.OpCode_MULSU16C, RHOpCodes.OpCode_MULSU32C,
			RHOpCodes.OpCode_MULU8C, RHOpCodes.OpCode_MULU16C, RHOpCodes.OpCode_MULU32C,
		};

		private static RHOpCodes[] CODES_4_2 = {
			RHOpCodes.OpCode_ADD64, RHOpCodes.OpCode_SUB64, RHOpCodes.OpCode_SHLL64, RHOpCodes.OpCode_SHRL64,
			RHOpCodes.OpCode_SHRA64, RHOpCodes.OpCode_ROTL64, RHOpCodes.OpCode_ROTR64, RHOpCodes.OpCode_MUL64,
		};

		private static RHOpCodes[] CODES_4_4 = {
			RHOpCodes.OpCode_ADD64C, RHOpCodes.OpCode_SUB64C, RHOpCodes.OpCode_MUL64C, RHOpCodes.OpCode_MULSU64C, RHOpCodes.OpCode_MULU64C,
		};
	}
}

using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;

namespace PacketCryptProof {
	internal static partial class RandHashInterpreter {
		[LibraryImport("packetcrypt.dll")]
		private static partial int RandHash_interpret(ReadOnlySpan<UInt32> progbuf, Span<Byte> ccState, Span<UInt32> memory, int progLen, UInt32 memorySizeBytes, int cycles);

		public unsafe static Boolean Interpret(Memory<UInt32> prog, Memory<Byte> ccState, Memory<Byte> memory, int cycles) {
			if (memory.Length != 256 * 4) throw new ArgumentOutOfRangeException("memory");
			if (ccState.Length != 2048) throw new ArgumentOutOfRangeException("ccState");

			Memory<Byte> ccState2 = ccState.ToArray();
			Memory<Byte> memory2 = memory.ToArray();

			RandHash_interpret(prog.ToArray(), ccState2.Span, MemoryMarshal.Cast<Byte, UInt32>(memory2.Span), prog.Length, (uint)memory.Length, cycles);

			var ctx = new Context();
			ctx.memory = memory;
			ctx.hashIn = ccState.Slice(0, ccState.Length / 2);
			ctx.hashOut = ccState.Slice(ccState.Length / 2, ccState.Length / 2);
			if (ccState.Length / 4 / 2 != 256) throw new ArgumentOutOfRangeException("ccState");
			ctx.prog = prog;

			for (int i = 0; i < cycles; i++) {
				ctx.opCtr = 0;
				interpret(ctx, 0);
				if (ctx.opCtr > 20000) {
					return false; // er.New("RandHash_TOO_LONG");
				} else if (ctx.opCtr < 0) {
					return false; //return er.New("RandHash_TOO_SHORT");
				}

				ctx.hashctr = 0;

				var tmp = ctx.hashOut;
				ctx.hashOut = ctx.hashIn;
				ctx.hashIn = tmp;
			}

			Debug.Assert(memory.Span.SequenceEqual(memory2.Span));
			for (int i = 0; i < 2048 / 4; i++) {
				if (MemoryMarshal.Cast<Byte, UInt32>(ccState.Span)[i] != MemoryMarshal.Cast<Byte, UInt32>(ccState2.Span)[i]) Console.WriteLine("Diff at {0}: good = {1:x08} bad = {2:x08}", i, MemoryMarshal.Cast<Byte, UInt32>(ccState2.Span)[i], MemoryMarshal.Cast<Byte, UInt32>(ccState.Span)[i]);
			}
			Debug.Assert(ccState.Span.SequenceEqual(ccState2.Span));

			return true;
		}

		class Context {
			public List<UInt32> stack = new List<uint>();
			public List<int> scopes = new List<int>();
			public int varCount;
			public int opCtr;
			public Memory<UInt32> prog;

			public Memory<Byte> hashIn;
			public Memory<Byte> hashOut;
			public Memory<Byte> memory;
			public Int64 hashctr;
			public int loopCycle;
		}

		[StructLayout(LayoutKind.Explicit)]
		struct Var32 {
			[FieldOffset(0)]
			public UInt32 U32;
			[FieldOffset(0)]
			public Int32 S32;

			[FieldOffset(0)]
			public UInt16 U16a;
			[FieldOffset(2)]
			public UInt16 U16b;

			[FieldOffset(0)]
			public Int16 S16a;
			[FieldOffset(2)]
			public Int16 S16b;

			[FieldOffset(0)]
			public Byte U8a;
			[FieldOffset(1)]
			public Byte U8b;
			[FieldOffset(2)]
			public Byte U8c;
			[FieldOffset(3)]
			public Byte U8d;

			[FieldOffset(0)]
			public SByte S8a;
			[FieldOffset(1)]
			public SByte S8b;
			[FieldOffset(2)]
			public SByte S8c;
			[FieldOffset(3)]
			public SByte S8d;

			public static implicit operator Var32(UInt32 v) { return new Var32() { U32 = v }; }
			public static implicit operator UInt32(Var32 v) { return v.U32; }
		}

		[StructLayout(LayoutKind.Explicit)]
		struct Var64 {
			[FieldOffset(0)]
			public UInt64 U64;
			[FieldOffset(0)]
			public Int64 S64;

			[FieldOffset(0)]
			public UInt32 U32a;
			[FieldOffset(4)]
			public UInt32 U32b;

			[FieldOffset(0)]
			public Int32 S32a;
			[FieldOffset(4)]
			public Int32 S32b;

			[FieldOffset(0)]
			public UInt16 U16a;
			[FieldOffset(2)]
			public UInt16 U16b;
			[FieldOffset(4)]
			public UInt16 U16c;
			[FieldOffset(6)]
			public UInt16 U16d;

			[FieldOffset(0)]
			public Int16 S16a;

			public static implicit operator Var64(UInt64 v) { return new Var64() { U64 = v }; }
			public static implicit operator UInt64(Var64 v) { return v.U64; }
			public static implicit operator UInt128(Var64 v) { return v.U64; }
			public static implicit operator Int128(Var64 v) { return v.U64; }
			public static explicit operator Int64(Var64 v) { return v.S64; }
		}

		private static UInt32 DecodeInsn_OP(UInt32 insn) {
			return insn & 0xff;
		}
		private static UInt32 DecodeInsn_MEMORY_STEP(UInt32 insn) {
			return (insn >> 13) & 15;
		}
		private static UInt32 DecodeInsn_MEMORY_BASE(UInt32 insn) {
			return insn >> 17;
		}
		private static UInt32 DecodeInsn_MEMORY_CARRY(UInt32 insn) {
			return (insn >> 9) & 15;
		}
		private static Int64 DecodeInsn_imm(UInt32 insn) {
			if ((insn & (1 << 19)) == 0) return (Int32)insn >> 20;
			var imm = insn >> 20;
			UInt64 ret;
			ret = 1ul << (int)(imm & 0x1F);
			imm >>= 5;
			ret ^= 1ul << (int)(imm & 0x1F);
			imm >>= 5;
			ret ^= ((UInt64)(imm & 1) << 63) - 1;
			imm >>= 1;
			ret |= (UInt64)(imm & 1) << 63;
			return (Int64)ret;
		}
		private static UInt32 DecodeInsn_REGA(UInt32 insn) {
			return (insn >> 9) & 0x1ff;
		}
		private static UInt32 DecodeInsn_REGB(UInt32 insn) {
			return (insn >> 20) & 0x1ff;
		}
		private static bool DecodeInsn_HAS_IMM(UInt32 insn) {
			return (insn & (1 << 18)) != 0;
		}
		private static Int32 DecodeInsn_immLo(UInt32 insn) {
			return (Int32)(DecodeInsn_imm(insn));
		}

		private static UInt32 getReg(List<UInt32> stack, UInt32 index) {
			return stack[(int)index];
		}
		private static UInt32 getA(Context ctx, UInt32 insn) {
			return getReg(ctx.stack, DecodeInsn_REGA(insn));
		}
		private static UInt32 getB(Context ctx, UInt32 insn) {
			if (DecodeInsn_HAS_IMM(insn)) return (UInt32) DecodeInsn_immLo(insn);
			return getReg(ctx.stack, DecodeInsn_REGB(insn));
		}
		private static UInt64 getA2(Context ctx, UInt32 insn) {
			uint rega = DecodeInsn_REGA(insn);
			return (UInt64)getReg(ctx.stack, rega - 1) | ((UInt64)getReg(ctx.stack, rega) << 32);
		}
		private static UInt64 getB2(Context ctx, UInt32 insn) {
			if (DecodeInsn_HAS_IMM(insn)) return (UInt64)DecodeInsn_imm(insn);
			uint regb = DecodeInsn_REGB(insn);
			return (UInt64)getReg(ctx.stack, regb - 1) | ((UInt64)getReg(ctx.stack, regb) << 32);
		}

		private static void out1(Context ctx, UInt32 val) {
			ctx.varCount++;
			ctx.stack.Add(val);
		}
		private static void out2(Context ctx, UInt64 a) {
			ctx.varCount += 2;
			ctx.stack.Add((UInt32)a);
			ctx.stack.Add((UInt32)(a >> 32));
		}
		private static void out4(Context ctx, UInt128 a) {
			ctx.varCount += 4;
			ctx.stack.Add((UInt32)a);
			ctx.stack.Add((UInt32)(a >> 32));
			ctx.stack.Add((UInt32)(a >> 64));
			ctx.stack.Add((UInt32)(a >> 96));
		}

		private static int branch(Context ctx, bool a, UInt32 insn, int pc) {
			if (DecodeInsn_imm(insn) != 2) throw new Exception("count should be 2");
			if (a) return interpret(ctx, pc + 2);
			return interpret(ctx, pc + 1);
		}

		private static void DEBUGF(String format, params Object[] args) {
			//Console.WriteLine(format, args);
		}

		private static void DEBUGS(String op, UInt32 a, UInt32 @out) {
			DEBUGF("{0:x08} -> {1:x08}", op, a, @out);
		}
		private static void DEBUGS(String op, UInt32 a, UInt32 b, UInt32 @out) {
			DEBUGF("{0:x08} {1:x08} -> {2:x08}", op, a, b, @out);
		}
		private static void DEBUGS(String op, UInt32 a, UInt32 b, UInt64 outl) {
			DEBUGF("{0:x08} {1:x08} -> {2:x08} {3:x08}", op, a, b, (UInt32)outl, (UInt32)(outl >> 32));
		}
		private static void DEBUGS(String op, UInt64 al, UInt64 bl, UInt64 outl) {
			DEBUGF("{0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", op, (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
		}
		private static void DEBUGS(String op, UInt64 al, UInt64 bl, UInt128 outx) {
			DEBUGF("{0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08} {6:x08} {7:x08}", op, (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outx, (UInt32)(outx >> 32), (UInt32)(outx >> 64), (UInt32)(outx >> 96));
		}

		private static int interpret(Context ctx, int pc) {
			if (pc != 0) {
				ctx.stack.Add(~0U);
				ctx.scopes.Add(ctx.varCount);
				ctx.varCount = 0;
			}
			for (; ; pc++) {
				if (ctx.opCtr > 20000) return -1;
				ctx.opCtr++;
				var insn = ctx.prog.Span[pc];
				var op = (RHOpCodes)(DecodeInsn_OP(insn));
				if (op <= RHOpCodes.OpCode_INVALID_ZERO || op > RHOpCodes.OpCode_END) throw new Exception("op out of range");
				switch (op) {
					case RHOpCodes.OpCode_MEMORY:
						var @base = (int)DecodeInsn_MEMORY_BASE(insn);
						var step = (int)DecodeInsn_MEMORY_STEP(insn);
						var carry = (int)DecodeInsn_MEMORY_CARRY(insn);
						var idx = (@base + ((ctx.loopCycle + carry) * step)) & (256 - 1);
						var hi = BitConverter.ToUInt32(ctx.memory.Span.Slice(idx * 4, 4));
						DEBUGF("MEMORY({0}, 0x{1:x08}, {2}, {3}) -> {4:x08} ({5:x08})", ctx.loopCycle, @base, step, carry, hi, idx);
						out1(ctx, hi);
						break;
					case RHOpCodes.OpCode_IN:
						var idx2 = (Int64)((UInt32)(DecodeInsn_imm(insn))) % 256;
						var hi2 = BitConverter.ToUInt32(ctx.hashIn.Span.Slice((int)idx2 * 4, 4));
						DEBUGF("IN {0} -> {1:x08}", idx2, hi2);
						out1(ctx, hi2);
						break;
					case RHOpCodes.OpCode_LOOP:
						DEBUGF("LOOP ({0:x08}) {1}", insn, pc);
						var count = (int)DecodeInsn_imm(insn);
						var ret = pc;
						for (int i = 0; i < count; i++) {
							ctx.loopCycle = i;
							ret = interpret(ctx, pc + 1);
						}
						if (ctx.opCtr > 20000) return -1;
						pc = ret;
						if (pc == ctx.prog.Length - 1) {
							if (ctx.stack.Count != 0) throw new Exception("leftover stack");
							if (ctx.scopes.Count != 0) throw new Exception("leftover scopes");
							if (ctx.varCount != 0) throw new Exception("varCount not 0");
							return pc;
						}
						break;
					case RHOpCodes.OpCode_IF_LIKELY:
						DEBUGF("IF_LIKELY ({0:x08}) {1}", insn, pc);
						pc = branch(ctx, (getA(ctx, insn) & 7) != 0, insn, pc);
						break;
					case RHOpCodes.OpCode_IF_RANDOM:
						DEBUGF("IF_RANDOM ({0:x08}) {1}", insn, pc);
						pc = branch(ctx, (getA(ctx, insn) & 1) != 0, insn, pc);
						break;
					case RHOpCodes.OpCode_JMP:
						DEBUGF("JMP ({0:x08}) {1}", insn, pc);
						var count2 = (insn >> 8);
						pc += (int)count2;
						break;
					case RHOpCodes.OpCode_END:
						DEBUGF("END ({0:x08}) {1}", insn, pc);
						// output everything first
						if (ctx.stack.Count - ctx.varCount <= 0) throw new Exception("insane varcount");
						for (int i = ctx.stack.Count - ctx.varCount; i < ctx.stack.Count; i++) {
							DEBUGF("OUTPUT {0:x08} ({1})", ctx.stack[i], ctx.hashctr);
							var h = BitConverter.ToUInt32(ctx.hashOut.Span.Slice((int)ctx.hashctr * 4, 4));
							h += ctx.stack[i];
							BitConverter.GetBytes(h).CopyTo(ctx.hashOut.Span.Slice((int)ctx.hashctr * 4, 4));
							ctx.hashctr = (ctx.hashctr + 1) % 256;
						}
						ctx.stack.RemoveRange(ctx.stack.Count - ctx.varCount, ctx.varCount);
						if (ctx.stack[ctx.stack.Count - 1] != ~0U) throw new Exception("corrupt stack");
						ctx.varCount = ctx.scopes[ctx.scopes.Count - 1];

						// pop pop
						ctx.stack.RemoveAt(ctx.stack.Count - 1);
						ctx.scopes.RemoveAt(ctx.scopes.Count - 1);

						return pc;
					default:
						doOp(ctx, insn, op);
						break;
				}
			}
		}

		private static void doOp(Context ctx, UInt32 insn, RHOpCodes op) {
			Var32 a, b, @out = new Var32();
			Var64 al, bl, outl = new Var64();
			UInt128 outx;
			switch (op) {
				case RHOpCodes.OpCode_POPCNT8:
					a = getA(ctx, insn);
					@out.U8a = (Byte)BitOperations.PopCount(a.U8a);
					@out.U8b = (Byte)BitOperations.PopCount(a.U8b);
					@out.U8c = (Byte)BitOperations.PopCount(a.U8c);
					@out.U8d = (Byte)BitOperations.PopCount(a.U8d);
					DEBUGS("POPCNT8", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_POPCNT16:
					a = getA(ctx, insn);
					@out.U16a = (UInt16)BitOperations.PopCount(a.U16a);
					@out.U16b = (UInt16)BitOperations.PopCount(a.U16b);
					DEBUGS("POPCNT16", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_POPCNT32:
					a = getA(ctx, insn);
					@out = (uint)BitOperations.PopCount(a);
					DEBUGS("POPCNT32", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CLZ8:
					a = getA(ctx, insn);
					@out.U8a = (Byte)(BitOperations.LeadingZeroCount(a.U8a) - 24);
					@out.U8b = (Byte)(BitOperations.LeadingZeroCount(a.U8b) - 24);
					@out.U8c = (Byte)(BitOperations.LeadingZeroCount(a.U8c) - 24);
					@out.U8d = (Byte)(BitOperations.LeadingZeroCount(a.U8d) - 24);
					DEBUGS("CLZ8", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CLZ16:
					a = getA(ctx, insn);
					@out.U16a = (UInt16)(BitOperations.LeadingZeroCount(a.U16a) - 16);
					@out.U16b = (UInt16)(BitOperations.LeadingZeroCount(a.U16b) - 16);
					DEBUGS("CLZ16", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CLZ32:
					a = getA(ctx, insn);
					@out.S32 = BitOperations.LeadingZeroCount(a);
					DEBUGS("CLZ32", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CTZ8:
					a = getA(ctx, insn);
					@out.U8a = (Byte)Math.Min(8, BitOperations.TrailingZeroCount(a.U8a));
					@out.U8b = (Byte)Math.Min(8, BitOperations.TrailingZeroCount(a.U8b));
					@out.U8c = (Byte)Math.Min(8, BitOperations.TrailingZeroCount(a.U8c));
					@out.U8d = (Byte)Math.Min(8, BitOperations.TrailingZeroCount(a.U8d));
					DEBUGS("CTZ8", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CTZ16:
					a = getA(ctx, insn);
					@out.U16a = (UInt16)Math.Min(16, BitOperations.TrailingZeroCount(a.U16a));
					@out.U16b = (UInt16)Math.Min(16, BitOperations.TrailingZeroCount(a.U16b));
					DEBUGS("CTZ16", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CTZ32:
					a = getA(ctx, insn);
					@out.S32 = BitOperations.TrailingZeroCount(a);
					DEBUGS("CTZ32", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_BSWAP16:
					a = getA(ctx, insn);
					@out.U16a = BinaryPrimitives.ReverseEndianness(a.U16a);
					@out.U16b = BinaryPrimitives.ReverseEndianness(a.U16b);
					DEBUGS("BSWAP16", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_BSWAP32:
					a = getA(ctx, insn);
					@out = BinaryPrimitives.ReverseEndianness(a);
					DEBUGS("BSWAP32", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U8a = (Byte)(a.U8a + b.U8a);
					@out.U8b = (Byte)(a.U8b + b.U8b);
					@out.U8c = (Byte)(a.U8c + b.U8c);
					@out.U8d = (Byte)(a.U8d + b.U8d);
					DEBUGS("ADD8", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U16a = (UInt16)(a.U16a + b.U16a);
					@out.U16b = (UInt16)(a.U16b + b.U16b);
					DEBUGS("ADD16", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a + b;
					DEBUGS("ADD32", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SUB8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U8a = (Byte)(a.U8a - b.U8a);
					@out.U8b = (Byte)(a.U8b - b.U8b);
					@out.U8c = (Byte)(a.U8c - b.U8c);
					@out.U8d = (Byte)(a.U8d - b.U8d);
					DEBUGS("SUB8", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SUB16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U16a = (UInt16)(a.U16a - b.U16a);
					@out.U16b = (UInt16)(a.U16b - b.U16b);
					DEBUGS("SUB16", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SUB32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a - b;
					DEBUGS("SUB32", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHLL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U8a = (Byte)(a.U8a << (b.U8a & 7));
					@out.U8b = (Byte)(a.U8b << (b.U8b & 7));
					@out.U8c = (Byte)(a.U8c << (b.U8c & 7));
					@out.U8d = (Byte)(a.U8d << (b.U8d & 7));
					DEBUGS("SHLL8", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHLL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U16a = (UInt16)(a.U16a << (b.U16a & 15));
					@out.U16b = (UInt16)(a.U16b << (b.U16b & 15));
					DEBUGS("SHLL16", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHLL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a << (b.S32 & 31);
					DEBUGS("SHLL32", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U8a = (Byte)(a.U8a >> (b.U8a & 7));
					@out.U8b = (Byte)(a.U8b >> (b.U8b & 7));
					@out.U8c = (Byte)(a.U8c >> (b.U8c & 7));
					@out.U8d = (Byte)(a.U8d >> (b.U8d & 7));
					DEBUGS("SHRL8", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U16a = (UInt16)(a.U16a >> (b.U16a & 15));
					@out.U16b = (UInt16)(a.U16b >> (b.U16b & 15));
					DEBUGS("SHRL16", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a >> (b.S32 & 31);
					DEBUGS("SHRL32", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRA8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U8a = (Byte)(a.S8a >> (b.U8a & 7));
					@out.U8b = (Byte)(a.S8b >> (b.U8b & 7));
					@out.U8c = (Byte)(a.S8c >> (b.U8c & 7));
					@out.U8d = (Byte)(a.S8d >> (b.U8d & 7));
					DEBUGS("SHRA8", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRA16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U16a = (UInt16)(a.S16a >> (b.U16a & 15));
					@out.U16b = (UInt16)(a.S16b >> (b.U16b & 15));
					DEBUGS("SHRA16", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRA32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.S32 = a.S32 >> (b.S32 & 31);
					DEBUGS("SHRA32", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ROTL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U8a = (Byte)((a.U8a << (b.U8a & 7)) | (a.U8a >> (8 - (b.U8a & 7))));
					@out.U8b = (Byte)((a.U8b << (b.U8b & 7)) | (a.U8b >> (8 - (b.U8b & 7))));
					@out.U8c = (Byte)((a.U8c << (b.U8c & 7)) | (a.U8c >> (8 - (b.U8c & 7))));
					@out.U8d = (Byte)((a.U8d << (b.U8d & 7)) | (a.U8d >> (8 - (b.U8d & 7))));
					DEBUGS("ROTL8", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ROTL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U16a = (UInt16)((a.U16a << (b.U16a & 15)) | (a.U16a >> (16 - (b.U16a & 15))));
					@out.U16b = (UInt16)((a.U16b << (b.U16b & 15)) | (a.U16b >> (16 - (b.U16b & 15))));
					DEBUGS("ROTL16", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ROTL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (a.U32 << (b.S32 & 31)) | (a.U32 >> ((32 - b.S32) & 31));
					DEBUGS("ROTL32", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_MUL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U8a = (Byte)(a.U8a * b.U8a);
					@out.U8b = (Byte)(a.U8b * b.U8b);
					@out.U8c = (Byte)(a.U8c * b.U8c);
					@out.U8d = (Byte)(a.U8d * b.U8d);
					DEBUGS("MUL8", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_MUL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out.U16a = (UInt16)(a.U16a * b.U16a);
					@out.U16b = (UInt16)(a.U16b * b.U16b);
					DEBUGS("MUL16", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_MUL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a * b;
					DEBUGS("MUL32", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_AND:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a & b;
					DEBUGS("AND", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_OR:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a | b;
					DEBUGS("OR", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_XOR:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a ^ b;
					DEBUGS("XOR", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U16a = (UInt16)((UInt16)a.U8a + (UInt16)b.U8a);
					outl.U16b = (UInt16)((UInt16)a.U8b + (UInt16)b.U8b);
					outl.U16c = (UInt16)((UInt16)a.U8c + (UInt16)b.U8c);
					outl.U16d = (UInt16)((UInt16)a.U8d + (UInt16)b.U8d);
					DEBUGS("ADD8C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U32a = (uint)a.U16a + (uint)b.U16a;
					outl.U32b = (uint)a.U16b + (uint)b.U16b;
					DEBUGS("ADD16C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)a + (UInt64)b;
					DEBUGS("ADD32C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U16a = (UInt16)((UInt16)a.U8a - (UInt16)b.U8a);
					outl.U16b = (UInt16)((UInt16)a.U8b - (UInt16)b.U8b);
					outl.U16c = (UInt16)((UInt16)a.U8c - (UInt16)b.U8c);
					outl.U16d = (UInt16)((UInt16)a.U8d - (UInt16)b.U8d);
					DEBUGS("SUB8C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U32a = (uint)((uint)a.U16a - (uint)b.U16a);
					outl.U32b = (uint)((uint)a.U16b - (uint)b.U16b);
					DEBUGS("SUB16C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)a - (UInt64)b;
					DEBUGS("SUB32C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U16a = (UInt16)((Int16)a.S8a * (Int16)b.S8a);
					outl.U16b = (UInt16)((Int16)a.S8b * (Int16)b.S8b);
					outl.U16c = (UInt16)((Int16)a.S8c * (Int16)b.S8c);
					outl.U16d = (UInt16)((Int16)a.S8d * (Int16)b.S8d);
					DEBUGS("MUL8C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.S32a = (int)a.S16a * (int)b.S16a;
					outl.S32b = (int)a.S16b * (int)b.S16b;
					DEBUGS("MUL16C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)((Int64)a.S32 * (Int64)b.S32);
					DEBUGS("MUL32C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULSU8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U16a = (UInt16)((Int16)a.S8a * (Int16)b.U8a);
					outl.U16b = (UInt16)((Int16)a.S8b * (Int16)b.U8b);
					outl.U16c = (UInt16)((Int16)a.S8c * (Int16)b.U8c);
					outl.U16d = (UInt16)((Int16)a.S8d * (Int16)b.U8d);
					DEBUGS("MULSU8C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULSU16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.S32a = (int)a.S16a * (int)b.U16a;
					outl.S32b = (int)a.S16b * (int)b.U16b;
					DEBUGS("MULSU16C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULSU32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)((Int64)a.S32 * (Int64)b);
					DEBUGS("MULSU32C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULU8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U16a = (UInt16)((UInt16)a.U8a * (UInt16)b.U8a);
					outl.U16b = (UInt16)((UInt16)a.U8b * (UInt16)b.U8b);
					outl.U16c = (UInt16)((UInt16)a.U8c * (UInt16)b.U8c);
					outl.U16d = (UInt16)((UInt16)a.U8d * (UInt16)b.U8d);
					DEBUGS("MULU8C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULU16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl.U32a = (uint)a.U16a * (uint)b.U16a;
					outl.U32b = (uint)a.U16b * (uint)b.U16b;
					DEBUGS("MULU16C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULU32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)a * (UInt64)b;
					DEBUGS("MULU32C", a, b, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = al + bl;
					DEBUGS("ADD64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = al - bl;
					DEBUGS("SUB64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SHLL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = (UInt64)(al << ((int)bl & 63));
					DEBUGS("SHLL64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SHRL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = (UInt64)(al >> ((int)bl & 63));
					DEBUGS("SHRL64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SHRA64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = (UInt64)((Int64)al >> ((int)bl & 63));
					DEBUGS("SHRA64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ROTL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = BitOperations.RotateLeft(al, (int)bl);
					DEBUGS("ROTL64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ROTR64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = BitOperations.RotateRight(al, (int)bl);
					DEBUGS("ROTR64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = al * bl;
					DEBUGS("MUL64", al, bl, outl);
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)al + (UInt128)bl;
					DEBUGS("ADD64C", al, bl, outx);
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_SUB64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)al - (UInt128)bl;
					DEBUGS("SUB64C", al, bl, outx);
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_MUL64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)((Int128)(Int64)al * (Int128)(Int64)bl);
					DEBUGS("MUL64C", al, bl, outx);
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_MULSU64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn); ;
					outx = (UInt128)((Int128)(Int64)al * (Int128)bl);
					DEBUGS("MULSU64C", al, bl, outx);
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_MULU64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)al * (UInt128)bl;
					DEBUGS("MULU64C", al, bl, outx);
					out4(ctx, outx);
					break;
				default:
					throw new Exception("unexpected instruction " + op.ToString());
					break;
			}
		}
	}
}

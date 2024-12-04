using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

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
			if ((insn & (1 << 19)) != 0) {
				var imm = insn >> 20;
				var a = imm & ((1 << 5) - 1);
				imm >>= 5;
				var b = imm & ((1 << 5) - 1);
				imm >>= 5;
				var i = imm & 1;
				imm >>= 1;
				var s = imm;
				var big1 = 1UL;
				var @out = (UInt64)((((UInt64)(i) << 63) - 1) ^ (big1 << (int)b) ^ (big1 << (int)a));
				imm <<= 1;
				imm >>= 1;
				big1 &= (UInt64)s;
				@out |= big1 << 63;
				return (Int64)@out;
			}
			return (Int32)(insn) >> 20;
		}
		private static UInt32 DecodeInsn_REGA(UInt32 insn) {
			return (insn >> 9) & 0x1ff;
		}
		private static UInt32 DecodeInsn_REGB(UInt32 insn) {
			return (insn >> 20) & 0x1ff;
		}
		private static bool DecodeInsn_HAS_IMM(UInt32 insn) {
			return ((insn >> 18) & 1) != 0;
		}
		private static Int32 DecodeInsn_immLo(UInt32 insn) {
			return (Int32)(DecodeInsn_imm(insn));
		}

		private static UInt32 getReg(IList<UInt32> stack, UInt32 index) {
			return stack[(int)index];
		}
		private static UInt32 getA(Context ctx, UInt32 insn) {
			return getReg(ctx.stack, DecodeInsn_REGA(insn));
		}
		private static UInt32 getB(Context ctx, UInt32 insn) {
			if (DecodeInsn_HAS_IMM(insn)) return (UInt32)(DecodeInsn_immLo(insn));
			return getReg(ctx.stack, DecodeInsn_REGB(insn));
		}
		private static UInt64 getA2(Context ctx, UInt32 insn) {
			return (UInt64)getReg(ctx.stack, DecodeInsn_REGA(insn) - 1) | ((UInt64)getReg(ctx.stack, DecodeInsn_REGA(insn)) << 32);
		}
		private static UInt64 getB2(Context ctx, UInt32 insn) {
			if (DecodeInsn_HAS_IMM(insn)) {
				var imm = DecodeInsn_imm(insn);
				return (UInt64)(UInt32)imm | ((UInt64)(UInt32)(imm >> 32) << 32);
			}
			return (UInt64)getReg(ctx.stack, DecodeInsn_REGB(insn) - 1) | ((UInt64)getReg(ctx.stack, DecodeInsn_REGB(insn)) << 32);
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

		//static TextWriter debugwriter = File.CreateText("randinterp.log");

		private static void DEBUGF(Context ctx, String format, params Object[] args) {
			//for (int i = 0; i < ctx.scopes.Count; i++) debugwriter.Write("  ");
			//debugwriter.Write("// ");
			//debugwriter.WriteLine(format, args);
			//debugwriter.Flush();
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
						DEBUGF(ctx, "MEMORY({0}, 0x{1:x08}, {2}, {3}) -> {4:x08} ({5:x08})", ctx.loopCycle, @base, step, carry, hi, idx);
						out1(ctx, hi);
						break;
					case RHOpCodes.OpCode_IN:
						var idx2 = (Int64)((UInt32)(DecodeInsn_imm(insn))) % 256;
						var hi2 = BitConverter.ToUInt32(ctx.hashIn.Span.Slice((int)idx2 * 4, 4));
						DEBUGF(ctx, "IN {0} -> {1:x08}", idx2, hi2);
						out1(ctx, hi2);
						break;
					case RHOpCodes.OpCode_LOOP:
						DEBUGF(ctx, "LOOP ({0:x08}) {1}", insn, pc);
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
						DEBUGF(ctx, "IF_LIKELY ({0:x08}) {1}", insn, pc);
						pc = branch(ctx, (getA(ctx, insn) & 7) != 0, insn, pc);
						break;
					case RHOpCodes.OpCode_IF_RANDOM:
						DEBUGF(ctx, "IF_RANDOM ({0:x08}) {1}", insn, pc);
						pc = branch(ctx, (getA(ctx, insn) & 1) != 0, insn, pc);
						break;
					case RHOpCodes.OpCode_JMP:
						DEBUGF(ctx, "JMP ({0:x08}) {1}", insn, pc);
						var count2 = (insn >> 8);
						pc += (int)count2;
						break;
					case RHOpCodes.OpCode_END:
						DEBUGF(ctx, "END ({0:x08}) {1}", insn, pc);
						// output everything first
						if (ctx.stack.Count - ctx.varCount <= 0) throw new Exception("insane varcount");
						for (int i = ctx.stack.Count - ctx.varCount; i < ctx.stack.Count; i++) {
							DEBUGF(ctx, "OUTPUT {0:x08} ({1})", ctx.stack[i], ctx.hashctr);
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
			UInt32 a, b, @out;
			UInt64 al, bl, outl;
			UInt128 outx;
			switch (op) {
				case RHOpCodes.OpCode_POPCNT8:
					a = getA(ctx, insn);
					@out = (uint)(Byte)BitOperations.PopCount((Byte)a);
					@out |= (uint)((Byte)BitOperations.PopCount((Byte)(a >> 8))) << 8;
					@out |= (uint)((Byte)BitOperations.PopCount((Byte)(a >> 16))) << 16;
					@out |= (uint)((Byte)BitOperations.PopCount((Byte)(a >> 24))) << 24;
					DEBUGF(ctx, "POPCNT8 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_POPCNT16:
					a = getA(ctx, insn);
					@out = (uint)(UInt16)BitOperations.PopCount((UInt16)a);
					@out |= (uint)((UInt16)BitOperations.PopCount((UInt16)(a >> 16))) << 16;
					DEBUGF(ctx, "POPCNT16 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_POPCNT32:
					a = getA(ctx, insn);
					@out = (uint)BitOperations.PopCount(a);
					DEBUGF(ctx, "POPCNT32 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CLZ8:
					a = getA(ctx, insn);
					@out = (uint)(Byte)(BitOperations.LeadingZeroCount((Byte)a) - 24);
					@out |= (uint)((Byte)(BitOperations.LeadingZeroCount((Byte)(a >> 8)) - 24)) << 8;
					@out |= (uint)((Byte)(BitOperations.LeadingZeroCount((Byte)(a >> 16)) - 24)) << 16;
					@out |= (uint)((Byte)(BitOperations.LeadingZeroCount((Byte)(a >> 24)) - 24)) << 24;
					DEBUGF(ctx, "CLZ8 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CLZ16:
					a = getA(ctx, insn);
					@out = (uint)(UInt16)(BitOperations.LeadingZeroCount((UInt16)a) - 16);
					@out |= (uint)((UInt16)(BitOperations.LeadingZeroCount((UInt16)(a >> 16)) - 16)) << 16;
					DEBUGF(ctx, "CLZ16 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CLZ32:
					a = getA(ctx, insn);
					@out = (uint)BitOperations.LeadingZeroCount(a);
					DEBUGF(ctx, "CLZ32 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CTZ8:
					a = getA(ctx, insn);
					@out = (uint)(Byte)Math.Min(8, BitOperations.TrailingZeroCount((Byte)a));
					@out |= (uint)((Byte)Math.Min(8, BitOperations.TrailingZeroCount((Byte)(a >> 8)))) << 8;
					@out |= (uint)((Byte)Math.Min(8, BitOperations.TrailingZeroCount((Byte)(a >> 16)))) << 16;
					@out |= (uint)((Byte)Math.Min(8, BitOperations.TrailingZeroCount((Byte)(a >> 24)))) << 24;
					DEBUGF(ctx, "CTZ8 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CTZ16:
					a = getA(ctx, insn);
					@out = (uint)(UInt16)Math.Min(16, BitOperations.TrailingZeroCount((UInt16)a));
					@out |= (uint)((UInt16)Math.Min(16, BitOperations.TrailingZeroCount((UInt16)(a >> 16)))) << 16;
					DEBUGF(ctx, "CTZ16 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_CTZ32:
					a = getA(ctx, insn);
					@out = (uint)BitOperations.TrailingZeroCount(a);
					DEBUGF(ctx, "CTZ32 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_BSWAP16:
					a = getA(ctx, insn);
					@out = (uint)(UInt16)BinaryPrimitives.ReverseEndianness((UInt16)a);
					@out |= (uint)((UInt16)BinaryPrimitives.ReverseEndianness((UInt16)(a >> 16))) << 16;
					DEBUGF(ctx, "BSWAP16 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_BSWAP32:
					a = getA(ctx, insn);
					@out = BinaryPrimitives.ReverseEndianness(a);
					DEBUGF(ctx, "BSWAP32 {0:x08} -> {1:x08}", a, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = ((a & 0x00FF00FF) + (b & 0x00FF00FF)) & 0x00FF00FF;
					@out |= ((a & 0xFF00FF00) + (b & 0xFF00FF00)) & 0xFF00FF00;
					DEBUGF(ctx, "ADD8 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = ((a & 0x0000FFFF) + (b & 0x0000FFFF)) & 0x0000FFFF;
					@out |= (a & 0xFFFF0000) + (b & 0xFFFF0000);
					DEBUGF(ctx, "ADD16 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a + b;
					DEBUGF(ctx, "ADD32 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SUB8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = ((a & 0x000000FF) - (b & 0x000000FF)) & 0x000000FF;
					@out |= ((a & 0x0000FF00) - (b & 0x0000FF00)) & 0x0000FF00;
					@out |= ((a & 0x00FF0000) - (b & 0x00FF0000)) & 0x00FF0000;
					@out |= (a & 0xFF000000) - (b & 0xFF000000);
					DEBUGF(ctx, "SUB8 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SUB16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = ((a & 0x0000FFFF) - (b & 0x0000FFFF)) & 0x0000FFFF;
					@out |= (a & 0xFFFF0000) - (b & 0xFFFF0000);
					DEBUGF(ctx, "SUB16 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SUB32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a - b;
					DEBUGF(ctx, "SUB32 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHLL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = ((a & 0x000000FF) << (int)(b & 7)) & 0x000000FF;
					@out |= ((a & 0x0000FF00) << (int)((b >> 8) & 7)) & 0x0000FF00;
					@out |= ((a & 0x00FF0000) << (int)((b >> 16) & 7)) & 0x00FF0000;
					@out |= ((a & 0xFF000000) << (int)((b >> 24) & 7)) & 0xFF000000;
					DEBUGF(ctx, "SHLL8 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHLL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(UInt16)((UInt16)a << ((UInt16)b & 15));
					@out |= (uint)((UInt16)((UInt16)(a >> 16) << ((UInt16)(b >> 16) & 15))) << 16;
					DEBUGF(ctx, "SHLL16 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHLL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a << (int)(b & 31);
					DEBUGF(ctx, "SHLL32 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(Byte)((Byte)a >> ((Byte)b & 7));
					@out |= (uint)((Byte)((Byte)(a >> 8) >> ((Byte)(b >> 8) & 7))) << 8;
					@out |= (uint)((Byte)((Byte)(a >> 16) >> ((Byte)(b >> 16) & 7))) << 16;
					@out |= (uint)((Byte)((Byte)(a >> 24) >> ((Byte)(b >> 24) & 7))) << 24;
					DEBUGF(ctx, "SHRL8 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(UInt16)((UInt16)a >> ((UInt16)b & 15));
					@out |= (uint)((UInt16)((UInt16)(a >> 16) >> ((UInt16)(b >> 16) & 15))) << 16;
					DEBUGF(ctx, "SHRL16 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a >> (int)(b & 31);
					DEBUGF(ctx, "SHRL32 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRA8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(Byte)((SByte)a >> ((Byte)b & 7));
					@out |= (uint)((Byte)((SByte)(a >> 8) >> ((Byte)(b >> 8) & 7))) << 8;
					@out |= (uint)((Byte)((SByte)(a >> 16) >> ((Byte)(b >> 16) & 7))) << 16;
					@out |= (uint)((Byte)((SByte)(a >> 24) >> ((Byte)(b >> 24) & 7))) << 24;
					DEBUGF(ctx, "SHRA8 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRA16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(UInt16)((Int16)a >> ((UInt16)b & 15));
					@out |= (uint)((UInt16)((Int16)(a >> 16) >> ((UInt16)(b >> 16) & 15))) << 16;
					DEBUGF(ctx, "SHRA16 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_SHRA32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (UInt32)((Int32)a >> (int)(b & 31));
					DEBUGF(ctx, "SHRA32 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ROTL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(Byte)(((Byte)a << ((Byte)b & 7)) | ((Byte)a >> (8 - (((Byte)b) & 7))));
					@out |= (uint)(Byte)(((Byte)(a >> 8) << ((Byte)(b >> 8) & 7)) | ((Byte)(a >> 8) >> (8 - (((Byte)(b >> 8)) & 7)))) << 8;
					@out |= (uint)(Byte)(((Byte)(a >> 16) << ((Byte)(b >> 16) & 7)) | ((Byte)(a >> 16) >> (8 - (((Byte)(b >> 16)) & 7)))) << 16;
					@out |= (uint)(Byte)(((Byte)(a >> 24) << ((Byte)(b >> 24) & 7)) | ((Byte)(a >> 24) >> (8 - (((Byte)(b >> 24)) & 7)))) << 24;
					DEBUGF(ctx, "ROTL8 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ROTL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(UInt16)(((UInt16)a << ((UInt16)b & 15)) | ((UInt16)a >> (16 - (((UInt16)b) & 15))));
					@out |= (uint)(UInt16)(((UInt16)(a >> 16) << ((UInt16)(b >> 16) & 15)) | ((UInt16)(a >> 16) >> (16 - (((UInt16)(b >> 16)) & 15)))) << 16;
					DEBUGF(ctx, "ROTL16 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ROTL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (a << ((int)b & 31)) | (a >> ((32 - (int)b) & 31));
					DEBUGF(ctx, "ROTL32 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_MUL8:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(Byte)((Byte)a * (Byte)b);
					@out |= (uint)((Byte)((Byte)(a >> 8) * (Byte)(b >> 8))) << 8;
					@out |= (uint)((Byte)((Byte)(a >> 16) * (Byte)(b >> 16))) << 16;
					@out |= (uint)((Byte)((Byte)(a >> 24) * (Byte)(b >> 24))) << 24;
					DEBUGF(ctx, "MUL8 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_MUL16:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = (uint)(UInt16)((UInt16)a * (UInt16)b);
					@out |= (uint)((UInt16)((UInt16)(a >> 16) * (UInt16)(b >> 16))) << 16;
					DEBUGF(ctx, "MUL16 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_MUL32:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a * b;
					DEBUGF(ctx, "MUL32 {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_AND:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a & b;
					DEBUGF(ctx, "AND {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_OR:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a | b;
					DEBUGF(ctx, "OR {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_XOR:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					@out = a ^ b;
					DEBUGF(ctx, "XOR {0:x08} {1:x08} -> {2:x08}", a, b, @out);
					out1(ctx, @out);
					break;
				case RHOpCodes.OpCode_ADD8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(UInt16)((UInt16)(Byte)a + (UInt16)(Byte)b);
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 8) + (UInt16)(Byte)(b >> 8))) << 16;
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 16) + (UInt16)(Byte)(b >> 16))) << 32;
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 24) + (UInt16)(Byte)(b >> 24))) << 48;
					DEBUGF(ctx, "ADD8C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(uint)((uint)(UInt16)a + (uint)(UInt16)b);
					outl |= (UInt64)((uint)((uint)(UInt16)(a >> 16) + (uint)(UInt16)(b >> 16))) << 32;
					DEBUGF(ctx, "ADD16C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)a + (UInt64)b;
					DEBUGF(ctx, "ADD32C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(UInt16)((UInt16)(Byte)a - (UInt16)(Byte)b);
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 8) - (UInt16)(Byte)(b >> 8))) << 16;
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 16) - (UInt16)(Byte)(b >> 16))) << 32;
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 24) - (UInt16)(Byte)(b >> 24))) << 48;
					DEBUGF(ctx, "SUB8C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(uint)((uint)(UInt16)a - (uint)(UInt16)b);
					outl |= (UInt64)((uint)((uint)(UInt16)(a >> 16) - (uint)(UInt16)(b >> 16))) << 32;
					DEBUGF(ctx, "SUB16C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)a - (UInt64)b;
					DEBUGF(ctx, "SUB32C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(UInt16)((Int16)(SByte)a * (Int16)(SByte)b);
					outl |= (UInt64)((UInt16)((Int16)(SByte)(a >> 8) * (Int16)(SByte)(b >> 8))) << 16;
					outl |= (UInt64)((UInt16)((Int16)(SByte)(a >> 16) * (Int16)(SByte)(b >> 16))) << 32;
					outl |= (UInt64)((UInt16)((Int16)(SByte)(a >> 24) * (Int16)(SByte)(b >> 24))) << 48;
					DEBUGF(ctx, "MUL8C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(uint)((int)(Int16)a * (int)(Int16)b);
					outl |= (UInt64)((uint)((int)(Int16)(a >> 16) * (int)(Int16)(b >> 16))) << 32;
					DEBUGF(ctx, "MUL16C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)((Int64)(Int32)a * (Int64)(Int32)b);
					DEBUGF(ctx, "MUL32C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULSU8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(UInt16)((Int16)(SByte)a * (Int16)(Byte)b);
					outl |= (UInt64)((UInt16)((Int16)(SByte)(a >> 8) * (Int16)(Byte)(b >> 8))) << 16;
					outl |= (UInt64)((UInt16)((Int16)(SByte)(a >> 16) * (Int16)(Byte)(b >> 16))) << 32;
					outl |= (UInt64)((UInt16)((Int16)(SByte)(a >> 24) * (Int16)(Byte)(b >> 24))) << 48;
					DEBUGF(ctx, "MULSU8C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULSU16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(uint)((int)(Int16)a * (int)(UInt16)b);
					outl |= (UInt64)((uint)((int)(Int16)(a >> 16) * (int)(UInt16)(b >> 16))) << 32;
					DEBUGF(ctx, "MULSU16C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULSU32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)((Int64)(Int32)a * (Int64)b);
					DEBUGF(ctx, "MULSU32C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULU8C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(UInt16)((UInt16)(Byte)a * (UInt16)(Byte)b);
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 8) * (UInt16)(Byte)(b >> 8))) << 16;
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 16) * (UInt16)(Byte)(b >> 16))) << 32;
					outl |= (UInt64)((UInt16)((UInt16)(Byte)(a >> 24) * (UInt16)(Byte)(b >> 24))) << 48;
					DEBUGF(ctx, "MULU8C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULU16C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)(uint)((uint)(UInt16)a * (uint)(UInt16)b);
					outl |= (UInt64)((uint)((uint)(UInt16)(a >> 16) * (uint)(UInt16)(b >> 16))) << 32;
					DEBUGF(ctx, "MULU16C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MULU32C:
					a = getA(ctx, insn);
					b = getB(ctx, insn);
					outl = (UInt64)a * (UInt64)b;
					DEBUGF(ctx, "MULU32C {0:x08} {1:x08} -> {2:x08} {3:x08}", a, b, (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = al + bl;
					DEBUGF(ctx, "ADD64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SUB64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = al - bl;
					DEBUGF(ctx, "SUB64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SHLL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = (UInt64)(al << (int)(bl & 63));
					DEBUGF(ctx, "SHLL64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SHRL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = (UInt64)(al >> (int)(bl & 63));
					DEBUGF(ctx, "SHRL64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_SHRA64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = (UInt64)((Int64)al >> (int)(bl & 63));
					DEBUGF(ctx, "SHRA64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ROTL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = BitOperations.RotateLeft(al, (int)bl);
					DEBUGF(ctx, "ROTL64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ROTR64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = BitOperations.RotateRight(al, (int)bl);
					DEBUGF(ctx, "ROTR64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_MUL64:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outl = al * bl;
					DEBUGF(ctx, "MUL64 {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outl, (UInt32)(outl >> 32));
					out2(ctx, outl);
					break;
				case RHOpCodes.OpCode_ADD64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)al + (UInt128)bl;
					DEBUGF(ctx, "ADD64C {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08} {6:x08} {7:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outx, (UInt32)(outx >> 32), (UInt32)(outx >> 64), (UInt32)(outx >> 96));
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_SUB64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)al - (UInt128)bl;
					DEBUGF(ctx, "SUB64C {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08} {6:x08} {7:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outx, (UInt32)(outx >> 32), (UInt32)(outx >> 64), (UInt32)(outx >> 96));
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_MUL64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)((Int128)(Int64)al * (Int128)(Int64)bl);
					DEBUGF(ctx, "MUL64C {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08} {6:x08} {7:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outx, (UInt32)(outx >> 32), (UInt32)(outx >> 64), (UInt32)(outx >> 96));
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_MULSU64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn); ;
					outx = (UInt128)((Int128)(Int64)al * (Int128)bl);
					DEBUGF(ctx, "MULSU64C {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08} {6:x08} {7:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outx, (UInt32)(outx >> 32), (UInt32)(outx >> 64), (UInt32)(outx >> 96));
					out4(ctx, outx);
					break;
				case RHOpCodes.OpCode_MULU64C:
					al = getA2(ctx, insn);
					bl = getB2(ctx, insn);
					outx = (UInt128)al * (UInt128)bl;
					DEBUGF(ctx, "MULU64C {0:x08} {1:x08} {2:x08} {3:x08} -> {4:x08} {5:x08} {6:x08} {7:x08}", (UInt32)al, (UInt32)(al >> 32), (UInt32)bl, (UInt32)(bl >> 32), (UInt32)outx, (UInt32)(outx >> 32), (UInt32)(outx >> 64), (UInt32)(outx >> 96));
					out4(ctx, outx);
					break;
				default:
					throw new Exception("unexpected instruction " + op.ToString());
					break;
			}
		}
	}
}

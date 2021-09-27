using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UbiqSecurity.Fpe.UnitTests
{
	[TestClass]
	public class FF3_1Tests
	{
		private readonly byte[] _key =
		{
			(byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
			(byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
			(byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
			(byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
			(byte)0x3b, (byte)0x80, (byte)0x6a, (byte)0xeb,
			(byte)0x63, (byte)0x08, (byte)0x27, (byte)0x1f,
			(byte)0x65, (byte)0xcf, (byte)0x33, (byte)0xc7,
			(byte)0x39, (byte)0x1b, (byte)0x27, (byte)0xf7,
		};
		private readonly byte[] _twk1 = 
		{
			(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
			(byte)0x00, (byte)0x00, (byte)0x00,
		};
		private readonly byte[] _twk2 = 
		{
			(byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
			(byte)0x35, (byte)0x34, (byte)0x33,
		};
		private readonly byte[] _twk3 = 
		{
			(byte)0x37, (byte)0x37, (byte)0x37, (byte)0x37,
			(byte)0x70, (byte)0x71, (byte)0x72,
		};

		private readonly string[] _pt = { "890121234567890000", "89012123456789abcde" };

		[TestMethod]
		public void Ubiq1()
		{
			Test(_key, _twk1, _pt[0], "075870132022772250", 10, 16);
		}

		[TestMethod]
	public void Ubiq2()
		{
			Test(_key, _twk2, _pt[0], "251467746185412673", 10, 16);
		}

		[TestMethod]
	public void Ubiq3()
		{
			Test(_key, _twk3, _pt[1], "dwb01mx9aa2lmi3hrfm", 36, 16);
		}

		[TestMethod]
	public void Ubiq4()
		{
			Test(_key, _twk1, _pt[0], "327701863379108161", 10, 24);
		}

		[TestMethod]
	public void Ubiq5()
		{
			Test(_key, _twk2, _pt[0], "738670454850774517", 10, 24);
		}

		[TestMethod]
	public void Ubiq6()
		{
			Test(_key, _twk3, _pt[1], "o3a1og390b5uduvwyw5", 36, 24);
		}

		[TestMethod]
	public void Ubiq7()
		{
			Test(_key, _twk1, _pt[0], "892299037726855422", 10, 32);
		}

		[TestMethod]
	public void Ubiq8()
		{
			Test(_key, _twk2, _pt[0], "045013216693726967", 10, 32);
		}

		[TestMethod]
	public void Ubiq9()
		{
			Test(_key, _twk3, _pt[1], "0sxaooj0jjj5qqfomh8", 36, 32);
		}

		private void Test(byte[] key, byte[] twk, string _pt, string CT, int radix, int keyLength)
		{
			var testKey = new byte[keyLength];
			Array.Copy(key, testKey, keyLength);
			string result;
			FF3_1 ctx;

			Assert.AreEqual(_pt.Length, CT.Length);

			ctx = new FF3_1(testKey, twk, radix);
			result = ctx.Encrypt(_pt);
			Assert.AreEqual(CT, result);

			result = ctx.Decrypt(CT);
			Assert.AreEqual(_pt, result);
		}
	}
}

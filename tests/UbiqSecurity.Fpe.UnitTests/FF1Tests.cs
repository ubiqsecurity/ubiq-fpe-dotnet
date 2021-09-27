using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UbiqSecurity.Fpe.UnitTests
{
	[TestClass]
	public class FF1Tests
	{
		private readonly byte[] _key = 
		{
			(byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
			(byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
			(byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
			(byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c,
			(byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
			(byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
			(byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
			(byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94
		};
		private readonly string[] _pt = { "0123456789", "0123456789abcdefghi" };
		private readonly byte[] _twk1 = { };
		private readonly byte[] _twk2 = 
		{
			(byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
			(byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
			(byte)0x31, (byte)0x30
		};
		private readonly byte[] _twk3 = 
		{
			(byte)0x37, (byte)0x37, (byte)0x37, (byte)0x37,
			(byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
			(byte)0x37, (byte)0x37, (byte)0x37
		};

		[TestMethod]
		public void Nist1()
		{
			Test(_key, _twk1, _pt[0], "2433477484", 10, 16);
		}

		[TestMethod]
		public void Nist2()
		{
			Test(_key, _twk2, _pt[0], "6124200773", 10, 16);
		}

		[TestMethod]
		public void Nist3()
		{
			Test(_key, _twk3, _pt[1], "a9tv40mll9kdu509eum", 36, 16);
		}

		[TestMethod]
		public void Nist4()
		{
			Test(_key, _twk1, _pt[0], "2830668132", 10, 24);
		}

		[TestMethod]
		public void Nist5()
		{
			Test(_key, _twk2, _pt[0], "2496655549", 10, 24);
		}

		[TestMethod]
		public void Nist6()
		{
			Test(_key, _twk3, _pt[1], "xbj3kv35jrawxv32ysr", 36, 24);
		}

		[TestMethod]
		public void Nist7()
		{
			Test(_key, _twk1, _pt[0], "6657667009", 10, 32);
		}

		[TestMethod]
		public void Nist8()
		{
			Test(_key, _twk2, _pt[0], "1001623463", 10, 32);
		}

		[TestMethod]
		public void Nist9()
		{
			Test(_key, _twk3, _pt[1], "xs8a0azh2avyalyzuwd", 36, 32);
		}

		[TestMethod]
		public void Ubiq1()
		{
			var key = Convert.FromBase64String("9KEW1u5AalOlbL4PSqexABzcClXKyWPPWs45BIizR3o=");
			var twk = Convert.FromBase64String("/X9LmUWjxTWttHIAJxFsoPSYfX8/26m7xA51N1/qpjw=");
			var PT = "000000000011000011011100011001001111000010001111110000100";
			var CT = "000001101011101010001111011101101011101100111010000100110";

			string result;
			FF1 ctx;

			Assert.AreEqual(PT.Length, CT.Length);

			ctx = new FF1(key, twk, 6, 32, 2);
			result = ctx.Encrypt(PT);
			Assert.AreEqual(CT, result);

			result = ctx.Decrypt(CT);
			Assert.AreEqual(PT, result);
		}

		[TestMethod]
		public void base2()
		{
			byte[] l_key =
			{
				(byte)0xF4, (byte)0xA1, (byte)0x16, (byte)0xD6,
				(byte)0xEE, (byte)0x40, (byte)0x6A, (byte)0x53,
				(byte)0xA5, (byte)0x6C, (byte)0xBE, (byte)0x0F,
				(byte)0x4A, (byte)0xA7, (byte)0xB1, (byte)0x00,
				(byte)0x1C, (byte)0xDC, (byte)0x0A, (byte)0x55,
				(byte)0xCA, (byte)0xC9, (byte)0x63, (byte)0xCF,
				(byte)0x5A, (byte)0xCE, (byte)0x39, (byte)0x04,
				(byte)0x88, (byte)0xB3, (byte)0x47, (byte)0x7A
			};
			byte[] l_tweak =
			{
				(byte)0xFD, (byte)0x7F, (byte)0x4B, (byte)0x99,
				(byte)0x45, (byte)0xA3, (byte)0xC5, (byte)0x35,
				(byte)0xAD, (byte)0xB4, (byte)0x72, (byte)0x00,
				(byte)0x27, (byte)0x11, (byte)0x6C, (byte)0xA0,
				(byte)0xF4, (byte)0x98, (byte)0x7D, (byte)0x7F,
				(byte)0x3F, (byte)0xDB, (byte)0xA9, (byte)0xBB,
				(byte)0xC4, (byte)0x0E, (byte)0x75, (byte)0x37,
				(byte)0x5F, (byte)0xEA, (byte)0xA6, (byte)0x3C
			};

			Test(l_key,
				 l_tweak,
				 "00000101011011011101001001010011100111100011001",
				 "10110101001110101101110000011000000011111100111",
				 2, 32);
		}

		private void Test(byte[] key, byte[] twk, string PT, string CT, int radix, int keyLength)
		{
			var testKey = new byte[keyLength];
			Array.Copy(key, testKey, keyLength);
			string result;
			FF1 ctx;

			Assert.AreEqual(PT.Length, CT.Length);

			ctx = new FF1(testKey, twk, 0, 0, radix);
			result = ctx.Encrypt(PT);
			Assert.AreEqual(CT, result);

			result = ctx.Decrypt(CT);
			Assert.AreEqual(PT, result);
		}
	}
}

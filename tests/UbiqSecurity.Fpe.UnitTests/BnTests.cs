using System;
using System.Numerics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UbiqSecurity.Fpe.UnitTests
{
	[TestClass]
	public class BnTests
	{
		[TestMethod]
		public void radix_exceptions()
		{
			// exception test for bad input
			Assert.ThrowsException<ArgumentException>(() => Bn.__bigint_set_str("109", "012345678"));
		
			Assert.ThrowsException<ArgumentException>(() => Bn.__bigint_set_str("109", ""));

			Assert.ThrowsException<ArgumentException>(() =>Bn.__bigint_get_str("", BigInteger.Zero));
		}

		[TestMethod]
		public void radix_edgecase()
		{
			//0 test
			BigInteger r1 = Bn.__bigint_set_str("0", "0123456789");
			Assert.AreEqual(r1, BigInteger.Zero);

			var output = Bn.__bigint_get_str("0123456789ABCDEF", r1);
			Assert.AreEqual(output, "0");

			output = Bn.__bigint_get_str("0123456789ABCDEF", BigInteger.Zero);
			Assert.AreEqual(output, "0");
		}

		[TestMethod]
		public void radix_dec2hex()
		{
			// dec2hex
			BigInteger r1 = Bn.__bigint_set_str("100", "0123456789");
			Assert.AreEqual(r1, new BigInteger(100));

			String output = Bn.__bigint_get_str("0123456789ABCDEF", r1);
			Assert.AreEqual(output, "64");
		}

		[TestMethod]
		public void radix_oct2hex()
		{
			// oct2hex
			BigInteger r1 = Bn.__bigint_set_str("100", "01234567");
			Assert.AreEqual(r1, new BigInteger(64));

			String output = Bn.__bigint_get_str("0123456789ABCDEF", r1);
			Assert.AreEqual(output, "40");
		}

		[TestMethod]
		public void radix_dec2dec()
		{
			// dec2dec
			BigInteger r1 = Bn.__bigint_set_str("@$#", "!@#$%^&*()");
			Assert.AreEqual(r1, new BigInteger(132));

			String output = Bn.__bigint_get_str("0123456789", r1);
			Assert.AreEqual(output, "132");
		}

		[TestMethod]
		public void radix_oct2dec()
		{
			// oct2dec
			BigInteger r1 = Bn.__bigint_set_str("@$#", "!@#$%^&*");
			Assert.AreEqual(r1, new BigInteger(90));

			String output = Bn.__bigint_get_str("0123456789", r1);
			Assert.AreEqual(output, "90");
		}
	}
}

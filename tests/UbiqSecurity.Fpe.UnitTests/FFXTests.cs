using System;
using System.Linq;
using System.Numerics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using UbiqSecurity.Fpe.Constants;

namespace UbiqSecurity.Fpe.UnitTests
{
	[TestClass]
	public class FFXTests
	{
		[TestMethod]
		public void Str_NoLeadingZero_Success()
		{
			var testString = "12345";
			BigInteger bigInt = new BigInteger(12345);

			var s = FFX.Str(5, 10, bigInt);

			Assert.AreEqual(testString, s);

		}

		[TestMethod]
		public void Str_LeadingZero_Success()
		{
			var testString = "012345";
			BigInteger bigInt = new BigInteger(012345);

			var s = FFX.Str(6, 10, bigInt);

			Assert.AreEqual(testString, s);
		}

		[TestMethod]
		public void Str_PadFront_Success()
		{
			string s;
			var testString = "00012345";
			BigInteger bigInt = new BigInteger(0012345);

			s = FFX.Str(8, 10, bigInt);

			Assert.AreEqual(testString, s);
		}

		
		[TestMethod]
		public void Str_TooLong_Fail()
		{
			BigInteger bigInt = new BigInteger(012345);

			var ex = Assert.ThrowsException<Exception>(() => FFX.Str(4, 10, bigInt));
			Assert.AreEqual(FPEExceptionConstants.MaxStringLength, ex.Message);
		}

		[TestMethod]
		public void Rev_Array_EvenLength_Success()
		{
			var a = new byte[] { 1, 2, 3, 4};
			var ra = new byte[] { 4, 3, 2, 1};

			var b = FFX.Rev(a);

			Assert.IsTrue(ra.SequenceEqual(b));
		}

		[TestMethod]
		public void Rev_Array_OddLength_Success()
		{
			var a = new byte[] {1, 2, 3, 4, 5};
			var ra = new byte[] { 5, 4, 3, 2, 1 };

			var b = FFX.Rev(a);

			Assert.IsTrue(ra.SequenceEqual(b));
		}

		[TestMethod]
		public void Rev_String_Success()
		{
			var s = "abcd";
			var rs = "dcba";

			var r = FFX.Rev(s);

			Assert.IsTrue(rs.SequenceEqual(r));
		}
	}
}

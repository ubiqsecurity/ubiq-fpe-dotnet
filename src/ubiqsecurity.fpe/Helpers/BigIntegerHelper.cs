using System;
using System.Linq;
using System.Numerics;
using System.Text;
using UbiqSecurity.Fpe.Constants;

namespace UbiqSecurity.Fpe.Helpers
{
	public static class BigIntegerHelper
	{
		public static BigInteger Mod(BigInteger value, BigInteger m)
		{
			BigInteger biggie = value % m;
			return biggie.Sign >= 0 ? biggie : biggie + m;
		}

		public static BigInteger Parse(string value, int radix)
		{
			string digits = "0123456789abcdefghijklmnopqrstuvwxyz";

			if (radix <= 1 || radix > 36)
			{
				throw new ArgumentOutOfRangeException(nameof(radix));
			}

			if (value == "")
			{
				value = digits.Substring(0, 1);
			}

			bool negative = value[0] == '-';

			if (negative)
			{
				value = value.Substring(1);
			}
			string rValue = value;
			BigInteger RetValue = 0;
			for (int i = 0; i < value.Length; i++)
			{
				int CharIdx = digits.IndexOf(char.ToLower(rValue[i]));
				if ((CharIdx >= radix) || (CharIdx < 0))
				{
					throw new ArgumentOutOfRangeException("Value", value, FPEExceptionConstants.InvalidCharacter);
				}

				RetValue = RetValue * radix + CharIdx;
			}

			return negative ? BigInteger.Negate(RetValue) : RetValue;
		}

		public static string ToRadixString(BigInteger value, int radix)
		{
			if (radix <= 1 || radix > 36)
			{
				throw new ArgumentOutOfRangeException(nameof(radix));
			}

			if (value == 0)
			{
				return "0";
			}

			bool negative = value.Sign == -1;

			if (negative)
			{
				value = BigInteger.Abs(value);
			}

			StringBuilder sb = new StringBuilder();

			for (; value > 0; value /= radix)
			{
				int d = (int)(value % radix);

				sb.Append((char)(d < 10 ? '0' + d : 'a' - 10 + d));
			}

			return (negative ? "-" : "") + string.Concat(sb.ToString().Reverse());
		}
	}
}

using System;
using System.Numerics;
using UbiqSecurity.Fpe.Constants;
using UbiqSecurity.Fpe.Helpers;

namespace UbiqSecurity.Fpe
{
	public class FF3_1 : FFX, IFFX
	{
		/// <summary>
		/// Constructs a new context object for the FF3-1 algorithm
		/// </summary>
		/// <param name="key">a byte array containing the key</param>
		/// <param name="twk">
		///		a byte array containing the "tweak" or IV. this value
		///		may not be null, and the number of bytes must be between
		///		the minimum and maximum allowed sizes
		/// </param>
		/// <param name="radix">
		///		the radix of the alphabet used for the plain and cipher
		///		text inputs/outputs
		/// </param>
		public FF3_1(byte[] key, byte[] twk, int radix)
			: base(FFX.Rev(key), twk, (long)(192.0 / (Math.Log(radix) / Math.Log(2))), 7, 7, radix)
		{

		}

		public override string Cipher(string x, byte[] twk, bool encrypt)
		{
			// Step 1
			int n = x.Length;
			int v = n / 2;
			int u = n - v;

			string A;
			string B;
			byte[][] Tw;
			byte[] P;

			// use default tweak if none is supplied
			if (twk == null)
			{
				twk = _twk;
			}

			// check text tweak if none is supplied
			if (n < _txtmin || n > _txtmax)
			{
				throw new ArgumentException(FPEExceptionConstants.InvalidInputLength);
			}
			else if (twk.Length < _twkmin || (_twkmax > 0 && twk.Length > _twkmax))
			{
				throw new ArgumentException(FPEExceptionConstants.InvalidTweakLength);
			}

			// Step 2
			if (encrypt)
			{
				A = x.Substring(0, u);
				B = x.Substring(u);
			}
			else
			{
				B = x.Substring(0, u);
				A = x.Substring(u);
			}

			// Step 3
			Tw = new byte[2][];
			Tw[0] = new byte[4];
			Tw[1] = new byte[4];


			Array.Copy(twk, 0, Tw[0], 0, 3);
			Tw[0][3] = (byte)(twk[3] & 0xf0);

			Array.Copy(twk, 4, Tw[1], 0, 3);
			Tw[1][3] = (byte)((twk[3] & 0x0f) << 4);

			P = new byte[16];

			for (int i = 0; i < 8; i++)
			{
				// Step 4i
				int m = (((i + (encrypt ? 1 : 0)) % 2) == 1) ? u : v;
				BigInteger c;
				BigInteger y;
				byte[] numb;
				byte[] base2Numb;

				// Step 4i, 4ii
				Array.Copy(Tw[(i + (encrypt ? 1 : 0)) % 2], 0, P, 0, 4);

				P[3] ^= (byte)(encrypt ? i : (7 - i));

				// reverse B and convert the numeral strin gto an 
				// integer. then, export that integer as an array.
				// store the array into the latter part of P
				c = BigIntegerHelper.Parse(FFX.Rev(B), _radix); ;

				base2Numb = c.ToByteArray();
				Array.Reverse(base2Numb);

				if (base2Numb[0] == 0 && base2Numb.Length > 1)
				{
					/*
					 * Per the Java documentation, BigInteger.toByteArray always
					 * returns enough bytes to contain a sign bit. For the purposes
					 * of this function all numbers are unsigned; however, when the
					 * most-significant bit is set in a number, the Java library
					 * returns an extra most-significant byte that is set to 0.
					 * That byte must be removed for the cipher to work correctly.
					 */
					numb = new byte[base2Numb.Length - 1];
					Array.Copy(base2Numb, 1, numb, 0, base2Numb.Length - 1);
				}
				else
				{
					numb = base2Numb;
				}

				if (12 <= numb.Length)
				{
					Array.Copy(numb, 0, P, 4, 12);
				}
				else
				{
					// zero pad on the left
					ArrayHelper.Fill(P, (byte)0, 4, P.Length - numb.Length);
					Array.Copy(numb, 0, P, P.Length - numb.Length, numb.Length);
				}

				// Step 4iv
				P = FFX.Rev(Ciph(FFX.Rev(P)));
				Array.Reverse(P);

				// Step 4v
				// calculate reverse(A) +/- y mode radix**m
				// where y is the number formed by the byte array P
				y = new BigInteger(P);
				y = BigIntegerHelper.Mod(y, BigInteger.One << (16 * 8));

				c = BigIntegerHelper.Parse(FFX.Rev(A), _radix);
				if (encrypt)
				{
					c = c + y;
				}
				else
				{
					c = c - y;
				}

				c = BigIntegerHelper.Mod(c, BigInteger.Pow(new BigInteger(_radix), m));

				// Step 4vii
				A = B;
				// Step 4vi
				B = FFX.Rev(FFX.Str(m, _radix, c));
			}

			// Step 5
			return encrypt ? (A + B) : (B + A);
		}
	}
}

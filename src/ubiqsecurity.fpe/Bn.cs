using System;
using System.Numerics;
using System.Text;
using UbiqSecurity.Fpe.Constants;

namespace UbiqSecurity.Fpe
{
	public class Bn
	{
		/// <summary>
		/// Convert a numerical value in a given alphabet to a number.
		/// An alphabet consists of single-byte symbols in which each
		/// symbol represents the numerical value associated with its
		/// index/position in the alphabet. for example, consider the
		/// alphabet: !@#$%^-*()
		///
		/// In this alphabet ! occupies index 0 and is therefore
		/// assigned that value. @ = 1, # = 2, etc. Furthermore, the
		/// alphabet contains 10 characters, so that becomes the radix
		/// of the input. Using the alphabet above, an input of @$#
		/// translates to a value of 132 (one hundred thirty-two,
		/// decimal).
		/// 
		/// If the alphabet above were instead: !@#$%^-*
		/// The radix would be 8 and an input of @$# translates to a
		/// value of 90 (ninety, decimal).
		/// </summary>
		/// <param name="str">the numerical value to be converted</param>
		/// <param name="alpha">alphabet consists of single-byte symbols</param>
		/// <returns>he numerical value of the str pattern position found in the alphabet</returns>
		public static BigInteger __bigint_set_str(string str, string alpha)
		{
			int len = str.Length;

			/*
			* the alphabet can be anything and doesn't have
			* to be in a recognized canonical order. the only
			* requirement is that every value in the list be
			* unique. checking that constraint is an expensive
			* undertaking, so it is assumed. as such, the radix
			* is simply the number of characters in the alphabet.
			*/
			int rad = alpha.Length;
			if (rad <= 0)
			{
				throw new ArgumentException(FPEExceptionConstants.InvalidAlphabetEmpty);
			}

			BigInteger m;
			BigInteger a;
			int i;
			BigInteger x;

			// represents the numerical value of str
			x = BigInteger.Zero;

			// multiplier used to multiply each digit
			// of the input into its correct position
			m = BigInteger.One;

			for (i = 0; i < len; i++)
			{
				int pos;

				// determine index/position in the alphabet.
				// if the character is not present the input is not valid.
				pos = alpha.IndexOf(str.Substring(len - 1 - i, 1));
				if (pos < 0)
				{
					throw new ArgumentException(FPEExceptionConstants.InvalidCharacter);
				}

				// multiply the digit into the correct position
				// and add it to the result
				a = m * new BigInteger(pos);
				x = x + a;
				m = m * new BigInteger(rad);
			}

			return x;
		}

		/// <summary>
		/// Inserts a character at a position in a String.
		///
		/// Convenience function returns String with inserted char
		/// at an index position.
		/// </summary>
		/// <param name="str">the original String</param>
		/// <param name="ch">the character to insert</param>
		/// <param name="position">the index position where to insert the ch</param>
		/// <returns>the new String containing the inserted ch </returns>
		public static string insertChar(string str, char ch, int position)
		{
			var sb = new StringBuilder(str);
			sb.Insert(position, ch);
			return sb.ToString();
		}

		/// <summary>
		/// Gets the str pattern of the alphabet given the numeric value.
		/// </summary>
		/// <param name="alpha">alphabet consists of single-byte symbols</param>
		/// <param name="x">the numerical value of the str pattern</param>
		/// <returns>the new String of the converted value </returns>
		public static string __bigint_get_str (string alpha, BigInteger x)
		{
			int rad = alpha.Length;
			BigInteger quotient = x;
			string str = string.Empty;
			char[] alphaArray = alpha.ToCharArray();

			if (rad <= 0)
			{
				throw new ArgumentException(FPEExceptionConstants.InvalidAlphabetEmpty);
			}

			/*
			 * to convert the numerical value, repeatedly
			 * divide (storing the resulted quotient and the remainder)
			 * by the desired radix of the output.
			 *
			 * the remainder is the current digit; the result
			 * of the division becomes the input to the next
			 * iteration
			*/
			while (quotient.CompareTo(BigInteger.Zero) != 0)
			{
				BigInteger rBigInt;
				quotient = BigInteger.DivRem(quotient, new BigInteger(rad), out rBigInt);
				var remainder = (int)rBigInt;
				str = insertChar(str, alphaArray[remainder], 0);
			}

			if (str.Length == 0)
			{
				str = insertChar(str, alphaArray[0], 0);
			}

			return str;
		}
	}
}

using System;
using System.Linq;
using System.Numerics;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using UbiqSecurity.Fpe.Constants;
using UbiqSecurity.Fpe.Helpers;

namespace UbiqSecurity.Fpe
{
	public abstract class FFX
	{
		protected readonly CbcBlockCipher _cipher;

		protected readonly int _radix;

		protected readonly long _txtmin, _txtmax;

		protected readonly long _twkmin, _twkmax;

		protected readonly byte[] _twk;

		protected FFX(byte[] key, byte[] twk, long txtmax, long twkmin, long twkmax, int radix)
		{
			// all 3 key sizes of AES are supported
			switch (key.Length)
			{
				case 16:
				case 24:
				case 32:
					break;
				default:
					throw new ArgumentException(FPEExceptionConstants.KeySize);
			}

			// FF1 and FF3-1 support a radix up to 65536, but the
			// implementation becomes increasingly difficult and
			// less useful in practice after the limits below.
			if (radix < 2 || radix > 36)
			{
				throw new ArgumentException(FPEExceptionConstants.InvalidRadix);
			}

			// for both ff1 and ff3-1: radix**minlen >= 1000000
			// 
			// therefore:
			// minlen = ceil(log_radix(1000000))
			//        = ceil(log_10(1000000) / log_10(radix))
			//        = ceil(6 / log_10(radix))
			long txtmin = (int)(Math.Ceiling((6 / Math.Log10(radix))));

			if (txtmin < 2 || txtmin > txtmax)
			{
				throw new Exception(FPEExceptionConstants.MinTextLengthRange);
			}

			// the default tweak must be specified
			if (twk == null)
			{
				throw new ArgumentNullException(FPEExceptionConstants.InvalidTweak);
			}

			// check tweak lengths
			if (twkmin > twkmax || twk.Length < twkmin || (twkmax > 0 && twk.Length > twkmax))
			{
				throw new ArgumentException(FPEExceptionConstants.InvalidTweakLength);
			}

			// the underlying cipher for FF1 and FF3-1 is AES in CBC mode.
			// by not specifying the IV, the IV is set to 0's which is
			// what is called for in these algorithms
			_cipher = new CbcBlockCipher(new AesEngine());
			_cipher.Init(true, new KeyParameter(key));

			_radix = radix;

			_txtmin = txtmin;
			_txtmax = txtmax;

			_twkmin = twkmin;
			_twkmax = twkmax;

			_twk = new byte[twk.Length];
			Array.Copy(twk, _twk, twk.Length);
		}

		public abstract string Cipher(string x, byte[] twk, bool encrypt);

		/// <summary>
		/// perform an aes-cbc encryption (with an IV of 0) of src, storing
		/// the last block of output into dst.The number of bytes in src
		/// must be a multiple of 16. dst and src may point to the same
		/// location but may not overlap, otherwise. dst must point to a
		/// location at least 16 bytes long
		/// </summary>
		protected void Prf(byte[] dst, int doff, byte[] src, int soff, int len)
		{
			if ((src.Length - soff) % _cipher.GetBlockSize() != 0)
			{
				throw new ArgumentException(FPEExceptionConstants.InvalidSourceLength);
			}

            // Some time, we want to run through process block for the entire src
            // sometimes just one block of the src, regardless of the length.
            // In cases where only one block needs to be processed, len would be
            // block size and will terminate the look.  In othercases, len will
            // be the size of the src but len - soff will terminate that.  however
            // cannot easily combine both checks into a single math equation.
            for (int i = 0; i < len && i < src.Length - soff; i += _cipher.GetBlockSize())
			{
				_cipher.ProcessBlock(src, soff + i, dst, doff);
			}

			_cipher.Reset();
		}

		/// <summary>
		/// perform an aes-ecb encryption of src. src and dst must each be
		/// 16 bytes long, starting from the respective offsets.src and dst
		/// may point to the same location or otherwise overlap
		/// </summary>
		protected void Ciph(byte[] dst, int doff, byte[] src, int soff)
		{
			Prf(dst, doff, src, soff, 16);
		}

		/// <summary>
		/// a convenience version of the ciph function that returns its
		/// output as a separate byte array
		/// </summary>
		protected byte[] Ciph(byte[] src)
		{
			byte[] dst = new byte[_cipher.GetBlockSize()];
			Ciph(dst, 0, src, 0);
			return dst;
		}

		/// <summary>
		/// reverse the bytes in a byte array. dst and src may point 
		/// to the same location but may not otherwise overlap
		/// </summary>
		public static void Rev(byte[] dst, byte[] src)
		{
			Array.Copy(src, dst, src.Length);
			Array.Reverse(dst);
		}

		/// <summary>
		/// convenience function that returns the reversed sequence
		/// of bytes as a new byte array
		/// </summary>
		public static byte[] Rev(byte[] src)
		{
			byte[] dst = new byte[src.Length];
			Rev(dst, src);
			return dst;
		}

		/// <summary>
		/// reverse the characters in a string
		/// </summary>
		public static string Rev(string str)
		{
			StringBuilder sb = new StringBuilder(str);
			return new string(sb.ToString().Reverse().ToArray());
		}

		/// <summary>
		/// Perform an exclusive-or of the corresponding bytes
		/// in two byte arrays
		/// </summary>
		public static void Xor(byte[] d, int doff,
							   byte[] s1, int s1off,
							   byte[] s2, int s2off,
							   int len)
		{
			for (int i = 0; i < len; i++)
			{
				d[doff + i] = (byte)(s1[s1off + i] ^ s2[s2off + i]);
			}
		}

		/// <summary>
		/// convert a big integer to a string under the radix r with
		/// length m. If the string is longer than m, the function fails.
		/// if the string is shorter that m, it is zero-padded to the left
		/// </summary>
		public static string Str(int m, int r, BigInteger i)
		{
			var s = BigIntegerHelper.ToRadixString(i, r);

			if (s.Length > m)
			{
				throw new Exception(FPEExceptionConstants.MaxStringLength);
			}

			if (s.Length < m)
			{
				s = s.PadLeft(m, '0');
			}

			return s;
		}

		/// <summary>
		/// Encrypt a string, returning a cipher text using the same alphabet.
		/// The key, tweak parameters, and radix were all already set
		/// by the initialization of the FF3_1 object.
		/// </summary>
		/// <param name="X">the plain text to be encrypted</param>
		/// <param name="twk">the tweak used to perturb the encryption</param>
		/// <returns>the encryption of the plain text, the cipher text</returns>
		public string Encrypt(string X, byte[] twk)
		{
			return Cipher(X, twk, true);
		}

		/// <summary>
		/// Encrypt a string, returning a cipher text using the same alphabet.
		/// The key, tweak parameters, and radix were all already set
		/// by the initialization of the FF3_1 object.
		/// </summary>
		/// <param name="X">The plain text to be encrypted</param>
		/// <returns>the encryption of the plain text, the cipher text</returns>
		public string Encrypt(string X)
		{
			return Encrypt(X, null);
		}

		/// <summary>
		/// Decrypt a string, returning the plain text.
		/// The key, tweak parameters, and radix were all already set
		/// by the initialization of the FF3_1 object.
		/// </summary>
		/// <param name="X">the cipher text to be decrypted</param>
		/// <param name="twk">the tweak used to perturb the encryption</param>
		/// <returns>the decryption of the cipher text, the plain text</returns>
		public string Decrypt(string X, byte[] twk)
		{
			return Cipher(X, twk, false);
		}

		/// <summary>
		/// Decrypt a string, returning the plain text.
		/// The key, tweak parameters, and radix were all already set
		/// by the initialization of the FF3_1 object.
		/// </summary>
		/// <param name="X">the cipher text to be decrypted</param>
		/// <returns>the decryption of the cipher text, the plain text</returns>
		public string Decrypt(string X)
		{
			return Decrypt(X, null);
		}
	}
}

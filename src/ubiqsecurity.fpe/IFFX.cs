namespace UbiqSecurity.Fpe
{
	public interface IFFX
	{
		string Cipher(string x, byte[] twk, bool encrypt);

		string Encrypt(string x, byte[] twk);

		string Encrypt(string x);

		string Decrypt(string x, byte[] twk);

		string Decrypt(string x);
	}
}

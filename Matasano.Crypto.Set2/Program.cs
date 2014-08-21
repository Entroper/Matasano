using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Matasano.Crypto.Set2
{
	class Program
	{
		private static Random _rng = new Random();
		private static RandomNumberGenerator _byteGenerator = RNGCryptoServiceProvider.Create();

		static void Main(string[] args)
		{
			//Problem9();
			//Problem10();
			Problem11();
		}

		public static void Problem9()
		{
			Console.WriteLine(Crypto.AddPkcs7Padding("YELLOW SUBMARINE".ToBytes(), 20).ToText());
		}

		public static void Problem10()
		{
			byte[] cipherBytes = ByteUtilities.Base64FileToBytes("10.txt");
			byte[] plainBytes = Crypto.Aes128CbcDecrypt(cipherBytes, "YELLOW SUBMARINE".ToBytes(), new byte[16]);
			plainBytes = Crypto.RemovePkcs7Padding(plainBytes, 16);

			Console.WriteLine(plainBytes.ToText());
		}

		public static void Problem11()
		{
			                 //          1         2         3         4
			                 // 123456789012345678901234567890123456789012345678
			string plainText = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

			for (int i = 0; i < 20; i++)
			{
				CipherMode mode;
				byte[] cipherBytes = P11Encrypt(plainText.ToBytes(), out mode);
				int matchingBlocks = ByteUtilities.CountMatchingBlocks(cipherBytes, 16);

				Console.WriteLine("Detected: {0} | Actual: {1}", matchingBlocks > 0 ? CipherMode.ECB : CipherMode.CBC, mode);
			}
		}

		private static byte[] P11Encrypt(byte[] plainBytes, out CipherMode mode)
		{
			byte[] prepend = new byte[_rng.Next(5, 11)];
			byte[] append = new byte[_rng.Next(5, 11)];
			_byteGenerator.GetBytes(prepend);
			_byteGenerator.GetBytes(append);

			plainBytes = prepend.Concat(plainBytes).Concat(append).ToArray();
			plainBytes = Crypto.AddPkcs7Padding(plainBytes, 16);

			byte[] key = new byte[16];
			_byteGenerator.GetBytes(key);

			if (_rng.Next(2) == 0)
			{
				mode = CipherMode.ECB;
				return Crypto.Aes128EcbEncrypt(plainBytes, key);
			}
			else
			{
				mode = CipherMode.CBC;
				byte[] iv = new byte[16];
				_byteGenerator.GetBytes(iv);
				return Crypto.Aes128CbcEncrypt(plainBytes, key, iv);
			}
		}
	}
}

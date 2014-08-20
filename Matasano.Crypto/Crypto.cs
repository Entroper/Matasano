using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Matasano.Crypto
{
	public static class Crypto
	{
		public static byte[] Aes128EcbDecrypt(byte[] cipherBytes, byte[] key)
		{
			var aes = new AesCryptoServiceProvider
			{
				KeySize = 128,
				Key = key,
				Mode = CipherMode.ECB,
				Padding = PaddingMode.Zeros
			};

			var decryptor = aes.CreateDecryptor();
			byte[] plainBytes = new byte[cipherBytes.Length];
			for (int offset = 0; offset < cipherBytes.Length; offset += aes.BlockSize/8)
			{
				decryptor.TransformBlock(cipherBytes, offset, aes.BlockSize/8, plainBytes, offset);
			}

			return plainBytes;
		}

		public static byte[] RemovePkcs7Padding(byte[] padded, int blockSize)
		{
			if (padded.Length % blockSize != 0)
				throw new InvalidOperationException("Input array length is not a multiple of blockSize");

			byte padding = padded[padded.Length - 1];
			if (padding < 1 || padding > blockSize)
				throw new InvalidOperationException("Input array is not PKCS#7 padded");

			for (int i = 1; i <= padding; i++)
			{
				if (padded[padded.Length - i] != padding)
					throw new InvalidOperationException("Input array is not PKCS#7 padded");
			}

			byte[] unpadded = new byte[padded.Length - padding];
			Buffer.BlockCopy(padded, 0, unpadded, 0, unpadded.Length);

			return unpadded;
		}
	}
}

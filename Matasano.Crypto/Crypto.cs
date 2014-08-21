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
		public static byte[] Aes128EcbEncrypt(byte[] plainBytes, byte[] key)
		{
			var aes = new AesCryptoServiceProvider
			{
				KeySize = 128,
				Key = key,
				Mode = CipherMode.ECB,
				Padding = PaddingMode.Zeros
			};

			var encryptor = aes.CreateEncryptor();
			byte[] cipherBytes = new byte[plainBytes.Length];
			for (int offset = 0; offset < plainBytes.Length; offset += aes.BlockSize/8)
			{
				encryptor.TransformBlock(plainBytes, offset, aes.BlockSize/8, cipherBytes, offset);
			}

			return cipherBytes;
		}

		public static byte[] Aes128CbcEncrypt(byte[] plainBytes, byte[] key, byte[] iv)
		{
			var aes = new AesCryptoServiceProvider
			{
				KeySize = 128,
				Key = key,
				Mode = CipherMode.ECB,
				Padding = PaddingMode.Zeros
			};

			if (iv.Length != aes.BlockSize/8)
				throw new InvalidOperationException("IV must be exactly one block length");

			var encryptor = aes.CreateEncryptor();
			byte[] cipherBytes = new byte[plainBytes.Length];
			
			byte[] block = new byte[16];
			for (int offset = 0; offset < plainBytes.Length; offset += aes.BlockSize/8)
			{
				Buffer.BlockCopy(plainBytes, 0, block, 0, aes.BlockSize/8);
				block = block.Xor(iv);
				encryptor.TransformBlock(block, 0, aes.BlockSize/8, cipherBytes, offset);
				Buffer.BlockCopy(cipherBytes, offset, iv, 0, aes.BlockSize/8);
			}

			return cipherBytes;
		}

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

		public static byte[] Aes128CbcDecrypt(byte[] cipherBytes, byte[] key, byte[] iv)
		{
			byte[] plainBytes = Aes128EcbDecrypt(cipherBytes, key);
			plainBytes = plainBytes.Xor(iv.Concat(cipherBytes).ToArray());

			return plainBytes;
		}

		public static byte[] AddPkcs7Padding(byte[] unpadded, int blockSize)
		{
			byte padding = (byte)(blockSize - unpadded.Length%blockSize);

			byte[] padded = new byte[unpadded.Length + padding];
			for (int i = unpadded.Length; i < padded.Length; i++)
				padded[i] = padding;

			Buffer.BlockCopy(unpadded, 0, padded, 0, unpadded.Length);

			return padded;
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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Matasano.Crypto
{
	public static class ByteUtilities
	{
		public static byte[] ToBytesFromHex(this string hex)
		{
			return Enumerable.Range(0, hex.Length)
			                 .Where(x => x%2 == 0)
			                 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
			                 .ToArray();
		}

		public static byte[] ToBytesFromBase64(this string base64)
		{
			return Convert.FromBase64String(base64);
		}

		public static string ToHex(this byte[] bytes)
		{
			return BitConverter.ToString(bytes).Replace("-", "");
		}

		public static string ToBase64(this byte[] bytes)
		{
			return Convert.ToBase64String(bytes);
		}

		public static byte[] ToBytes(this string text)
		{
			return Encoding.Default.GetBytes(text);
		}

		public static string ToText(this byte[] bytes)
		{
			return Encoding.Default.GetString(bytes);
		}

		public static byte[] Xor(this byte[] lhs, byte[] rhs)
		{
			var ret = new byte[lhs.Length];
			
			
			for (int i = 0, j = 0; i < lhs.Length; i++, j++)
			{
				if (j >= rhs.Length)
					j = 0;

				ret[i] = (byte)(lhs[i] ^ rhs[j]);
			}

			return ret;
		}

		public static bool ContentsEqual(this byte[] lhs, byte[] rhs)
		{
			if (lhs.Length != rhs.Length)
				return false;

			for (int i = 0; i < lhs.Length; i++)
				if (lhs[i] != rhs[i])
					return false;

			return true;
		}

		public static int HammingWeight(int b)
		{
			int weight = 0;
			while (b > 0)
			{
				weight += b & 1;
				b >>= 1;
			}

			return weight;
		}

		public static int HammingDistance(byte[] lhs, byte[] rhs)
		{
			if (lhs.Length != rhs.Length)
				throw new InvalidOperationException("Hamming distance must be between byte arrays of the same length");

			return lhs.Xor(rhs).Sum(b => HammingWeight(b));
		}

		public static int GetBlockSize(byte[] cipherBytes)
		{
			int bestBlockSize = 2;
			int bestNormalizedHamming = int.MaxValue;
			for (int blockSize = 2; blockSize <= 64; blockSize++)
			{
				byte[] lhs = new byte[blockSize*10];
				byte[] rhs = new byte[blockSize*10];
				Buffer.BlockCopy(cipherBytes, 0, lhs, 0, blockSize*10);
				Buffer.BlockCopy(cipherBytes, blockSize*8, rhs, 0, blockSize*10);

				int hamming = HammingDistance(lhs, rhs);
				if (hamming/blockSize < bestNormalizedHamming)
				{
					bestNormalizedHamming = hamming/blockSize;
					bestBlockSize = blockSize;
				}
			}
			return bestBlockSize;
		}

		public static byte[][] GetTransposedBlocks(int bestBlockSize, byte[] cipherBytes)
		{
			byte[][] transposedBlocks = new byte[bestBlockSize][];
			for (int i = 0; i < bestBlockSize; i++)
			{
				transposedBlocks[i] = new byte[cipherBytes.Length/bestBlockSize];
				for (int j = 0; j < cipherBytes.Length/bestBlockSize; j++)
				{
					transposedBlocks[i][j] = cipherBytes[i + j*bestBlockSize];
				}
			}
			return transposedBlocks;
		}

		public static byte[] Base64FileToBytes(string filename)
		{
			string contents;
			using (var fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
			using (var sr = new StreamReader(fs))
			{
				contents = sr.ReadToEnd();
			}

			return contents.Replace("\n", "").ToBytesFromBase64();
		}
	}
}

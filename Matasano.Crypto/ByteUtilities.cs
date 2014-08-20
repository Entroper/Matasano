using System;
using System.Collections.Generic;
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
	}
}

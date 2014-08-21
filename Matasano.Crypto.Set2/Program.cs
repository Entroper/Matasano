using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Matasano.Crypto.Set2
{
	class Program
	{
		static void Main(string[] args)
		{
			//Problem9();
			Problem10();
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
	}
}

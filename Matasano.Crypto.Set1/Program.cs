using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Matasano.Crypto.Set1
{
	class Program
	{
		static void Main(string[] args)
		{
			//Problem1();
			//Problem2();
			//Problem3();
			//Problem4();
			//Problem5();
			//Problem6Test();
			//Problem6();
			//Problem7();
			Problem8();
		}

		private static void Problem1()
		{
			string hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
			string base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

			Console.WriteLine("{0}\nbecomes\n{1}", hex, hex.ToBytesFromHex().ToBase64());
			Console.WriteLine("{0}\nbecomes\n{1}", base64, base64.ToBytesFromBase64().ToHex());
		}

		private static void Problem2()
		{
			string lhs = "1c0111001f010100061a024b53535009181c";
			string rhs = "686974207468652062756c6c277320657965";
			string answer = lhs.ToBytesFromHex().Xor(rhs.ToBytesFromHex()).ToHex();
			string expectedAnswer = "746865206b696420646f6e277420706c6179";

			Console.WriteLine("{0}\nXOR\n{1}\nis\n{2}\nand should be\n{3}", lhs, rhs, answer, expectedAnswer);
		}

		private static void Problem3()
		{
			string cipherText = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
			var cipherBytes = cipherText.ToBytesFromHex();

			var bestKey = CharacterFrequency.GetBestKey(cipherBytes);

			Console.WriteLine("Best key is 0x{0,2:X2}", bestKey);
			Console.WriteLine("Plaintext is {0}", cipherBytes.Xor(new[] { bestKey }).ToText());
		}

		private static void Problem4()
		{
			string bestline = String.Empty;

			using (var fs = new FileStream("4.txt", FileMode.Open, FileAccess.Read, FileShare.Read))
			using (var sr = new StreamReader(fs))
			{
				string line;
				int bestScore = int.MaxValue;
				while ((line = sr.ReadLine()) != null)
				{
					var key = CharacterFrequency.GetBestKey(line.ToBytesFromHex());
					string plainText = line.ToBytesFromHex().Xor(new[] { key }).ToText();
					var score = CharacterFrequency.GetScore(plainText);
					if (score < bestScore)
					{
						bestScore = score;
						bestline = plainText;
					}

					//Console.WriteLine("{0}: {1}", plainText, score);
				}
			}

			Console.WriteLine(bestline);
		}

		private static void Problem5()
		{
			string plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
			byte[] key = "ICE".ToBytes();

			string cipherText = plaintext.ToBytes().Xor(key).ToHex();
			Console.WriteLine(cipherText);
		}

		private static void Problem6Test()
		{
			Console.WriteLine(ByteUtilities.HammingDistance("this is a test".ToBytes(), "wokka wokka!!!".ToBytes()));
		}

		private static void Problem6()
		{
			var cipherBytes = ByteUtilities.Base64FileToBytes("6.txt");
			var blockSize = ByteUtilities.GetBlockSize(cipherBytes);

			Console.WriteLine("Best block size: {0}", blockSize);

			var transposedBlocks = ByteUtilities.GetTransposedBlocks(blockSize, cipherBytes);

			byte[] key = new byte[blockSize];
			for (int i = 0; i < blockSize; i++)
			{
				key[i] = CharacterFrequency.GetBestKey(transposedBlocks[i]);
			}

			Console.WriteLine("Key: {0}", key.ToText());
			Console.WriteLine(cipherBytes.Xor(key).ToText());
		}

		private static void Problem7()
		{
			byte[] cipherBytes = ByteUtilities.Base64FileToBytes("7.txt");

			var plainBytes = Crypto.Aes128EcbDecrypt(cipherBytes, "YELLOW SUBMARINE".ToBytes());
			var unpadded = Crypto.RemovePkcs7Padding(plainBytes, 16);

			Console.WriteLine(unpadded.ToText());
		}

		private static void Problem8()
		{
			using (var fs = new FileStream("8.txt", FileMode.Open, FileAccess.Read, FileShare.Read))
			using (var sr = new StreamReader(fs))
			{
				string line;
				while ((line = sr.ReadLine()) != null)
				{
					int matches = ByteUtilities.CountMatchingBlocks(line.ToBytesFromHex(), 16);

					if (matches > 0)
					{
						Console.WriteLine("{0} matches", matches);
						Console.WriteLine(line);
					}
				}
			}
		}
	}
}

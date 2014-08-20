using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Matasano.Crypto
{
	public static class CharacterFrequency
	{
		private static readonly string ExpectedRanking = " etaoinshrdlcumwfgypbvkjxqz";

		public static byte GetBestKey(byte[] cipherBytes)
		{
			byte bestKey = 0;
			int bestScore = int.MaxValue;
			foreach (byte b in Enumerable.Range(0, 255))
			{
				var plainBytes = cipherBytes.Xor(new[] { b });
				var plainText = plainBytes.ToText();

				var score = GetScore(plainText);
				if (score < bestScore)
				{
					bestScore = score;
					bestKey = b;
				}

				//Console.WriteLine("{0,2:X2}: {1}", b, score);
			}

			return bestKey;
		}

		public static int GetScore(string text)
		{
			var rankings = GetRankings(text);

			int score = rankings.Sum(c =>
			{
				int expectedIndex = ExpectedRanking.IndexOf(c);
				return expectedIndex == -1 ? 100 : Math.Abs(expectedIndex - rankings.IndexOf(c));
			});

			return score;
		}

		public static string GetRankings(string text)
		{
			text = text.ToLower();

			var frequencies = new Dictionary<char, double>();
			foreach (char c in text)
			{
				if (frequencies.ContainsKey(c))
					frequencies[c] = frequencies[c] + 1;
				else
					frequencies[c] = 1;
			}

			var rankings = frequencies.ToList();
			rankings.Sort((lhs, rhs) => rhs.Value.CompareTo(lhs.Value));

			return new string(rankings.Select(kvp => kvp.Key).ToArray());
		}
	}
}

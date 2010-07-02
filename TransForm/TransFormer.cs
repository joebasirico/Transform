using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Collections.Specialized;
using System.Globalization;
using System.Security.Cryptography;

namespace TransForm
{
	static class TransFormer
	{
		public static string ValidateWithStringInfo(string input)
		{
			StringInfo si = new StringInfo(input);
			return si.String;
		}

		public static string URLDecode(string input)
		{
			return HttpUtility.UrlDecode(input);
		}

		public static string HTMLDecode(string input)
		{
			return HttpUtility.HtmlDecode(input);
		}

		public static string BasicHTMLEncode(string input)
		{
			return HttpUtility.HtmlEncode(input);
		}

		public static string BasicURLEncode(string input)
		{
			return HttpUtility.UrlEncode(input);
		}

		public static string ParseQueryString(string input)
		{
			NameValueCollection nvc = HttpUtility.ParseQueryString(input);
			string output = "";

			output = "   [INDEX] KEY        VALUE\r\n";
			for (int i = 0; i < nvc.Count; i++)
				output += String.Format("   [{0}]     {1,-20} {2}\r\n", i, nvc.GetKey(i), nvc.Get(i));

			return output;
		}

		public static string ForceFullJavaScriptEncode(string input)
		{
			return ConvertStringToHexString(input, "\\x{0:x2}");
		}

		public static string ForceFullHTMLEncode(string input)
		{
			return ConvertStringToHexString(input, "&#x{0:x2};");
		}

		public static string ForceFullURLEncode(string input)
		{
			return ConvertStringToHexString(input, "%{0:x2}");
		}

		public static string ConvertStringToHexString(string input)
		{
			return ConvertStringToHexString(input, "{0:x2}");
		}

		public static string ConvertStringToHexString(string input, string format)
		{
			StringBuilder hex = new StringBuilder();
			foreach (char c in input)
			{
				hex.Append(String.Format(format, (uint)c));
			}
			return hex.ToString();
		}

		public static string Base64Encode(string utf8Text)
		{
			return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(utf8Text));
		}

		public static string Base64Decode(string textToTransform)
		{
			try
			{
				byte[] toDecodeByte = Convert.FromBase64String(textToTransform);

				System.Text.UTF8Encoding encoder = new System.Text.UTF8Encoding();
				System.Text.Decoder utf8Decode = encoder.GetDecoder();

				int charCount = utf8Decode.GetCharCount(toDecodeByte, 0, toDecodeByte.Length);

				char[] decodedChar = new char[charCount];
				utf8Decode.GetChars(toDecodeByte, 0, toDecodeByte.Length, decodedChar, 0);
				return new String(decodedChar);
			}
			catch
			{
				return "Invalid input: This does not seem to be a valid Base64 encoded string. Try adding an equals or two on the end ;)";
			}
		}

		public static string CRC16(string input)
		{
			string answer = "hex: ";
			string hexEncodedString = "";
			answer += hexEncodedString = BytesToHexString(ComputeChecksumBytes(Encoding.ASCII.GetBytes(input)));
			answer += "\r\nbin: " + Convert.ToString(Convert.ToInt32(hexEncodedString, 16), 2);

			return answer;
		}

		private static byte[] ComputeChecksumBytes(byte[] bytes)
		{
			ushort crc = ComputeCRC16(bytes);
			return new byte[] { (byte)(crc >> 8), (byte)(crc & 0x00ff) };
		}

		public static ushort ComputeCRC16(byte[] bytes)
		{
			const ushort polynomial = 0xA001;
			ushort[] table = new ushort[256];

			///////////////////////////////////////
			ushort value;
			ushort temp;
			for (ushort i = 0; i < table.Length; ++i)
			{
				value = 0;
				temp = i;
				for (byte j = 0; j < 8; ++j)
				{
					if (((value ^ temp) & 0x0001) != 0)
					{
						value = (ushort)((value >> 1) ^ polynomial);
					}
					else
					{
						value >>= 1;
					}
					temp >>= 1;
				}
				table[i] = value;
			}

			///////////////////////////////////

			ushort crc = 0;
			for (int i = 0; i < bytes.Length; ++i)
			{
				byte index = (byte)(crc ^ bytes[i]);
				crc = (ushort)((crc >> 8) ^ table[index]);
			}
			return crc;
		}

		public static string CRC32(string input)
		{
			string answer = "hex: ";
			string hexEncodedString = "";
			answer += hexEncodedString = BytesToHexString(BitConverter.GetBytes(ComputeCRC32(Encoding.ASCII.GetBytes(input))));
			answer += "\r\nbin: " + Convert.ToString(Convert.ToInt32(hexEncodedString, 16), 2);

			return answer;
		}

		internal static uint ComputeCRC32(byte[] bytes)
		{
			uint[] table;

			////////////////////////////

			uint poly = 0xedb88320;
			table = new uint[256];
			uint temp = 0;
			for (uint i = 0; i < table.Length; ++i)
			{
				temp = i;
				for (int j = 8; j > 0; --j)
				{
					if ((temp & 1) == 1)
					{
						temp = (uint)((temp >> 1) ^ poly);
					}
					else
					{
						temp >>= 1;
					}
				}
				table[i] = temp;
			}

			////////////////////////////////

			uint crc = 0xffffffff;
			for (int i = 0; i < bytes.Length; ++i)
			{
				byte index = (byte)(((crc) & 0xff) ^ bytes[i]);
				crc = (uint)((crc >> 8) ^ table[index]);
			}
			return ~crc;
		}


		public static string MD5(string input)
		{
			MD5CryptoServiceProvider hasher = new MD5CryptoServiceProvider();
			return ComputeHash(input, hasher);
		}

		public static string SHA1(string input)
		{
			SHA1CryptoServiceProvider hasher = new SHA1CryptoServiceProvider();
			return ComputeHash(input, hasher);
		}

		public static string SHA256(string input)
		{
			SHA256CryptoServiceProvider hasher = new SHA256CryptoServiceProvider();
			return ComputeHash(input, hasher);
		}

		public static string SHA384(string input)
		{
			SHA384CryptoServiceProvider hasher = new SHA384CryptoServiceProvider();
			return ComputeHash(input, hasher);
		}

		public static string SHA512(string input)
		{
			SHA512CryptoServiceProvider hasher = new SHA512CryptoServiceProvider();
			return ComputeHash(input, hasher);
		}

		private static string ComputeHash(string input, HashAlgorithm hasher)
		{
			string answer = "hex: ";
			byte[] hashBytes = hasher.ComputeHash(Encoding.ASCII.GetBytes(input));
			answer += BytesToHexString(hashBytes);
			answer += "\r\nbin: " + ConvertHexStringToBinaryString(hashBytes);
			return answer;
		}

		public static string ConvertHexStringToBinaryString(byte[] input)
		{
			//this is just for the tryparses
			string inputString = Encoding.ASCII.GetString(input);
			
			//first lets try to see if the input is an int, if it's just an int then let's convert it as such.
			Int64 tryInt = 0;
			if(Int64.TryParse(inputString, out tryInt))
				return Convert.ToString(tryInt, 2);

			StringBuilder answer = new StringBuilder();

			foreach (byte b in input)
			{
				answer.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
			}

			return answer.ToString();
		}

		private static string BytesToHexString(byte[] Hash)
		{
			string StringVersion = "";

			foreach (byte b in Hash)
			{
				string hexChar = b.ToString("x");
				if (hexChar.Length == 1)
					hexChar = "0" + hexChar;
				StringVersion += hexChar;
			}
			return StringVersion;
		}
	}
}
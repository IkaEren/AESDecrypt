using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;
using System.Text;

namespace AESDecrypt
{
    class Program
    {
		public byte[] EncodeToHexArray(string hex)
		{
			if (string.IsNullOrWhiteSpace(hex))
			{
				return null;
			}
			int length = hex.Length;
			byte[] array = new byte[length / 2];
			for (int i = 0; i < length; i += 2)
			{
				array[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			}
			return array;
		}

		public string HexArrayToString(byte[] ba)
		{
			if (ba == null)
			{
				return null;
			}
			return BitConverter.ToString(ba).Replace("-", "");
		}

		public string Decrypt(string key, string ciphertext, string tag, string nonce, string associatedText = null)
		{
			byte[] array = EncodeToHexArray(tag);
			byte[] array2 = EncodeToHexArray(ciphertext);
			byte[] key2 = EncodeToHexArray(key);
			byte[] associatedText2 = new byte[0];
			byte[] source = EncodeToHexArray(nonce);
			if (!string.IsNullOrWhiteSpace(associatedText))
			{
				associatedText2 = EncodeToHexArray(associatedText);
			}
			CcmBlockCipher ccmBlockCipher = new CcmBlockCipher(new AesEngine());
			AeadParameters parameters = new AeadParameters(new KeyParameter(key2), 128, source.Take(12).ToArray(), associatedText2);
			byte[] array3 = new byte[array2.Length + array.Length];
			Array.Copy(array2, 0, array3, 0, array2.Length);
			Array.Copy(array, 0, array3, array2.Length, array.Length);
			ccmBlockCipher.Init(forEncryption: false, parameters);
			byte[] array4 = new byte[ccmBlockCipher.GetOutputSize(array3.Length)];
			int outOff = ccmBlockCipher.ProcessBytes(array3, 0, array3.Length, array4, 0);
			ccmBlockCipher.DoFinal(array4, outOff);
			return Encoding.UTF8.GetString(array4);
		}

		static void Main(string[] args)
        {
			Program program = new Program();
			Console.Write("Enter your OTP: ");
			string otp_hex = int.Parse(Console.ReadLine()).ToString("X5");
			string key = int.Parse(DateTime.Now.ToString("ddMM")).ToString("X3") + "053786654500000000000000" + otp_hex;
			Console.Write("Enter your Cipher Text [ID / Password]: ");
			string ciphertext = Console.ReadLine();
			Console.Write("Enter your ID / Password tag: ");
			string tag = Console.ReadLine();
			Console.Write("Enter your IV: ");
			string s = Console.ReadLine();
			string nonce = program.HexArrayToString(Encoding.ASCII.GetBytes(s));
			Console.WriteLine("Your decrypted text is: " + program.Decrypt(key, ciphertext, tag, nonce));
			Console.ReadKey();
        }
    }
}

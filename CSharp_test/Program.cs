using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace CSharp_test
{
    class Program
    {
//        private const string PLAIN_TEXT = "id=1234567890abcd,timestamp=1234567890";

        //16進数文字列
        private const string KEY = "8e94b31ddaffbce26447d4af349a4b5f8a181388c30c28e52da66f2730c5f97d";
        private const string IV = "45e3e4ab8702e96e46c04df016c41283";
        private const string ENCED = "eU13U3FCVENkc1BrZE41aEhvK01kcUVxL09BZVF2bEJwNEZ1Nm14cU1xUThabFB2U2FtODNRbEY0cGdHWVJFTzBtTU1wazZvTXRiOHNYNnppd0l2ekdjbFpPN2wzdHRuK1RDK2lsQnJyalFWaytaTlFqemNTV3VYYWlkQzFJRTN4Y3hwN3VUMS9MbFA0R05XSytxclk3UUFyQmhlc2NDQXRrd05vTmVuajM5OGlnWXo4OE4vZ1NYdnVENWlMdzJoTEQxYlE2ek9OMXQzVGs4RUtpcm5SRnQraG1wMDhOMWFySnMyc2tCa0gwSzJra1pmSnloejRCcWt1aHIyU0wyc3hnamlBTmNGeFBSaU1LV0RYUmo0WjdGNHpKalN4R2RNUVVpT1ZiWnVJSHhJU2E2NENkUHJCMGg4SVlNRUVaenFCT2grbVlGTGNBNzdiQU9CL3c3YXhtbE1Jb0VkS0k2UDRPbUIxcHY0Y1JtZTJwR0M5TE05Y1NBRmxINUU3cXIxakdldVVZOHE5OTJNY1dmeTZ2emJVWXBWSnNVNFVNVXVFblZxLy9SN3huVTViMWI4ZlRGVytSNlhNdkdMa1pQQXRsODJ6N3c0cTE1UkN4cTFwS1lpL1EzbVRLZjJIR3VCSEF0YlkyUjdnWnd1cGxseGplWGdxbGM2SnN5UnBuaG1KcGoxNU9lRDdPRy92anFNRWx2dzhocm51alVueEFYRHhEeFd4NWM2UFM1dngvditPNjFQamZPbjFRc3NRUjVlWnpxTFFKSGRsNXl6eDJEQ29ZakR3V3RGWi9lZ1VyK2R3MW9SNVgvTTJyR09rb3Vjd2pobzVMblJsbVhwT1A3bQ==";

        private static PaddingMode PADDING;


        static void Main(string[] args)
        {
            byte[] key = ConvertHexStringToBytes(KEY);
            byte[] iv = ConvertHexStringToBytes(IV);
                
            for (int i = 2; i <= 5; i++)
            {
                try
                {
                    PADDING = (PaddingMode)i;


                    //Encrypt
//                    Byte[] encrypted = EncryptStringToBytes(PLAIN_TEXT, key, iv);

                    //Decrypt
                    string roundtrip = DecryptStringFromBytes(Convert.FromBase64String(ENCED), key, iv);

//                    Console.WriteLine(PADDING.ToString() + " : " + Convert.ToBase64String(encrypted));
                    Console.WriteLine(PADDING.ToString() + " : " + roundtrip);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }


        /// <summary>
        /// 16進数文字列をbyte配列へ変換
        /// </summary>
        /// <param name="hexString">16進数文字列</param>
        /// <returns>byte配列</returns>
        static byte[] ConvertHexStringToBytes(string hexString)
        {
            List<byte> bytes = new List<byte>();

            //文字列を2文字ずつ取得
            foreach (Match m in Regex.Matches(hexString, "(..)"))
            {
                byte b = Convert.ToByte(m.Value, 16);
                bytes.Add(b);
            }

            return bytes.ToArray();
        }


        /// <summary>
        /// 暗号化(AES256-CBC)
        /// </summary>
        /// <param name="plainText">平文</param>
        /// <param name="Key">鍵</param>
        /// <param name="IV">初期化ベクトル</param>
        /// <returns>暗号化したByte配列</returns>
        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.KeySize = 256;
                rijAlg.BlockSize = 128;
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Padding = PADDING;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }


        /// <summary>
        /// 復号化(AES256-CBC)
        /// </summary>
        /// <param name="cipherText">平文</param>
        /// <param name="Key">鍵</param>
        /// <param name="IV">初期化ベクトル</param>
        /// <returns>複合した文字列</returns>
        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.KeySize = 256;
                rijAlg.BlockSize = 128;
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Padding = PADDING;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

    }
}

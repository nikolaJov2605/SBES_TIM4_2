using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class AES_CBC
    {
        //public static void EncryptData(string message, byte[] key, out byte[] encryptMessage)
        //{
        //    AesCryptoServiceProvider aesCriptograph = new AesCryptoServiceProvider()
        //    {
        //        Key = key,
        //        Padding = PaddingMode.None,
        //        Mode = CipherMode.CBC
        //    };

        //    aesCriptograph.GenerateIV();//za blok podataka
        //    ICryptoTransform encryption = aesCriptograph.CreateEncryptor();

        //    byte[] msg = Encoding.ASCII.GetBytes(message);

        //    using (MemoryStream ms =  new MemoryStream())
        //    {
        //        using (CryptoStream cs = new CryptoStream(ms, encryption, CryptoStreamMode.Write))
        //        {
        //            cs.Write(msg, 0, msg.Length);
        //            encryptMessage = aesCriptograph.IV.Concat(msg.ToArray()).ToArray();
        //        }
        //    }
        //}

        public static byte[] EncryptData(string plainText, byte[] Key)
        {
            byte[] encrypted;
            byte[] IV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                aesAlg.GenerateIV();
                IV = aesAlg.IV;

                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption. 
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[IV.Length + encrypted.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

            // Return the encrypted bytes from the memory stream. 
            return combinedIvCt;

        }

        public static string DecryptData(byte[] cipherTextCombined, byte[] Key)
        {

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption. 
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
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

        //public static void DecryptData(string encryptedMessage, byte[] key, out string plainText)
        //{
        //    //Pravimo provajdera koji ce sadrzati kako se kriptuje
        //    AesCryptoServiceProvider aesCriptograph = new AesCryptoServiceProvider()
        //    {
        //        Key = key,
        //        Padding = PaddingMode.None,
        //        Mode = CipherMode.CBC
        //    };
        //    aesCriptograph.IV = Encoding.ASCII.GetBytes(encryptedMessage).Take(aesCriptograph.BlockSize / 8).ToArray();
        //    ICryptoTransform decryption = aesCriptograph.CreateDecryptor();

        //    byte[] decRip = Encoding.ASCII.GetBytes(encryptedMessage);

        //    using(MemoryStream ms = new MemoryStream(decRip.Skip(aesCriptograph.BlockSize / 8).ToArray()))
        //    {
        //        using(CryptoStream cs = new CryptoStream(ms, decryption, CryptoStreamMode.Read))
        //        {
        //            byte[] ret = new byte[decRip.Length - aesCriptograph.BlockSize / 8];
        //            cs.Read(ret, 0, ret.Length);
        //            plainText = Encoding.UTF8.GetString(ret);
        //        }
        //    }

        //}
    }
}

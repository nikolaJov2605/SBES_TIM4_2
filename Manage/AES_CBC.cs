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
        public static void EncryptData(string message,byte[] key,out string encryptMessage)
        {
            //Pravimo provajdera koji ce sadrzati kako se kriptuje
            AesCryptoServiceProvider aesCriptograph = new AesCryptoServiceProvider()
            {
                Key = key,
                Padding = PaddingMode.None,
                Mode = CipherMode.CBC
            };
            aesCriptograph.GenerateIV();//za blok podataka
            ICryptoTransform encryption = aesCriptograph.CreateEncryptor();

            using(MemoryStream data =  new MemoryStream())
            {
                using (CryptoStream stream = new CryptoStream(data, encryption, CryptoStreamMode.Write))
                {
                    stream.Write(ASCIIEncoding.ASCII.GetBytes(message), 0, message.Length);
                    encryptMessage = data.ToString();
                }
            }
        }

        public static void DecryptData(string encryptedMessage , byte[] key , out string plainText)
        {
            //Pravimo provajdera koji ce sadrzati kako se kriptuje
            AesCryptoServiceProvider aesCriptograph = new AesCryptoServiceProvider()
            {
                Key = key,
                Padding = PaddingMode.None,
                Mode = CipherMode.CBC
            };
            aesCriptograph.IV = ASCIIEncoding.ASCII.GetBytes(encryptedMessage).Take(aesCriptograph.BlockSize / 8).ToArray();
            ICryptoTransform decryption = aesCriptograph.CreateDecryptor();

            byte[] decRip = ASCIIEncoding.ASCII.GetBytes(encryptedMessage);
            using(MemoryStream data = new MemoryStream(decRip))
            {
                using(CryptoStream cs = new CryptoStream(data, decryption, CryptoStreamMode.Read))
                {
                    byte[] ret = new byte[decRip.Length - aesCriptograph.BlockSize / 8];
                    cs.Read(ret, 0, ret.Length);
                    plainText = ret.ToString();
                }
            }

        }
    }
}

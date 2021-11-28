using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace ServiceManager
{
    public class ServiceManagerImplementation : IServiceManager
    {
        string keyForStart = null;
        //Implementacija Servisa koji vraca kljuc i na nalog klijenta podize obicne servise :D
        [PrincipalPermission(SecurityAction.Demand,Role = "ExchangeSessionKey")]
        public string Connect()
        {
            //samo radi probe povezujemo samo RBAC i  kriptovanje danas za pocetak
            SymmetricAlgorithm syim = AesCryptoServiceProvider.Create();
            keyForStart = syim.Key.ToString();
            return ASCIIEncoding.ASCII.GetString(syim.Key);
        }
        [PrincipalPermission(SecurityAction.Demand, Role = "RunService")]
        public bool StartNewService(string encryptedMessage)
        {
            string data;
            AES_CBC.DecryptData(encryptedMessage, keyForStart, out data);
            Console.WriteLine(data);
            return false;
        }
    }
}

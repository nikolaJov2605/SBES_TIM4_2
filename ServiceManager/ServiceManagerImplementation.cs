using Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace ServiceManager
{
    public class ServiceManagerImplementation : IServiceManager
    {
        //Implementacija Servisa koji vraca kljuc i na nalog klijenta podize obicne servise :D
        [PrincipalPermission(SecurityAction.Demand,Role = "ExchangeSessionKey")]
        public string Connect()
        {
            //samo radi probe povezujemo samo RBAC i  kriptovanje danas za pocetak
            return "aaaaa";
            throw new NotImplementedException();
        }
        [PrincipalPermission(SecurityAction.Demand, Role = "RunService")]
        public bool StartNewService(string encryptedMessage)
        {
            
            return false;
        }
    }
}

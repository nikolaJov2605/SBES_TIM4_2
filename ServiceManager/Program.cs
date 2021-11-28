using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.IdentityModel.Policy;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;

namespace ServiceManager
{
    class Program
    {
        static void Main(string[] args)
        {

            NetTcpBinding binding = new NetTcpBinding();
            string address = "net.tcp://localhost:9999/WCFService";
            //Windows autetifikacija vezbe 1 /2 
            //binding.Security.Mode = SecurityMode.Transport;
            //binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            //binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;


            ServiceHost host = new ServiceHost(typeof(ServiceManagerImplementation));
            host.AddServiceEndpoint(typeof(IServiceManager), binding, address);
           
            // podesavamo da se koristi MyAuthorizationManager umesto ugradjenog
            host.Authorization.ServiceAuthorizationManager = new CustomAuthorizationManager();

           //dodajemo polisu          
            host.Authorization.PrincipalPermissionMode = PrincipalPermissionMode.Custom;

            List<IAuthorizationPolicy> polices = new List<IAuthorizationPolicy>();
            polices.Add(new CustomAuthorizationPolicy());

            host.Authorization.ExternalAuthorizationPolicies = polices.AsReadOnly();



            host.Open();
            Console.WriteLine("Server is successfully opened");
            Console.ReadLine();
        }
    }
}

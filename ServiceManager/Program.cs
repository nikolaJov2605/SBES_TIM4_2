using AuditManager;
using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.IdentityModel.Policy;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ServiceManager
{
    class Program
    {
        static void Main(string[] args)
        {

            NetTcpBinding binding = new NetTcpBinding();
            string address = "net.tcp://localhost:8888/WCFService";
            //Windows autetifikacija vezbe 1 /2 
            binding.Security.Mode = SecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

            ServiceHost host = new ServiceHost(typeof(ServiceManagerImplementation));
            host.AddServiceEndpoint(typeof(IServiceManager), binding, address);

            
            host.Authorization.ServiceAuthorizationManager = new CustomAuthorizationManager();

            // TO DO : podesesiti custom polisu, odnosno nas objekat principala           
            host.Authorization.PrincipalPermissionMode = PrincipalPermissionMode.Custom;

            List<IAuthorizationPolicy> polices = new List<IAuthorizationPolicy>();
            polices.Add(new CustomAuthorizationPolicy());

            host.Authorization.ExternalAuthorizationPolicies = polices.AsReadOnly();

            // Podesavanje AuditBehavior-a
            ServiceSecurityAuditBehavior newAudit = new ServiceSecurityAuditBehavior();
            newAudit.AuditLogLocation = AuditLogLocation.Application;
            newAudit.ServiceAuthorizationAuditLevel = AuditLevel.SuccessOrFailure;

            host.Description.Behaviors.Remove<ServiceSecurityAuditBehavior>();
            host.Description.Behaviors.Add(newAudit);


            host.Open();
            Console.WriteLine(WindowsIdentity.GetCurrent().Name);
            Console.WriteLine("Server is successfully opened");

            string srvCertCN = "Auditer";

            binding = new NetTcpBinding();
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

            /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
            X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, srvCertCN);
            EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                      new X509CertificateEndpointIdentity(srvCert));

            //using (AuditClient proxy = new AuditClient(binding, addressAudit))
            //{
            //    /// 1. Communication test
            //    proxy.TestCommunication();
            //}
            Console.ReadLine();
        }
    }
}

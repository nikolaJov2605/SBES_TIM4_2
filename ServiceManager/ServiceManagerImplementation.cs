using AuditManager;
using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.ServiceModel;
using System.Text;
using System.Threading;
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

        //[PrincipalPermission(SecurityAction.Demand, Role = "RunService")]
        public bool StartNewService(string encryptedMessage)
        {
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Manage.Formatter.ParseName(principal.Identity.Name);

            if(Thread.CurrentPrincipal.IsInRole("RunService"))
            {
                string data;
                AES_CBC.DecryptData(encryptedMessage, keyForStart, out data);
                Console.WriteLine(data);

                try
                {
                    //Audit.Audit.ServiceStarted(userName);
                    NetTcpBinding binding = new NetTcpBinding();
                    binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                    /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
                    X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
                    EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                              new X509CertificateEndpointIdentity(srvCert));
                    using (AuditClient proxy = new AuditClient(binding, addressAudit))
                    {
                        proxy.LogAuthorizationSuccess(userName, OperationContext.Current.IncomingMessageHeaders.Action);
                        proxy.LogServiceStarted(userName);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            else
            {
                try
                {
                    //Audit.Audit.ServiceStartDenied();
                    NetTcpBinding binding = new NetTcpBinding();
                    binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                    /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
                    X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
                    EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                              new X509CertificateEndpointIdentity(srvCert));
                    using (AuditClient proxy = new AuditClient(binding, addressAudit))
                    {
                        proxy.LogAuthorizationFailed(userName, OperationContext.Current.IncomingMessageHeaders.Action, "StartNewService need RunService permission");
                        proxy.LogServiceStartDenied();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }

                throw new FaultException("User " + userName +
                    " tried to start service without RunService role.");
            }

            return false;
        }
    }
}

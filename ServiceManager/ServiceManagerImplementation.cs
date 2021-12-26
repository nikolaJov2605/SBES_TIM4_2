using AuditManager;
using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Formatter = Manage.Formatter;

namespace ServiceManager
{
    public class ServiceManagerImplementation : IServiceManager
    {
        Dictionary<string, byte[]> UsersSessionKeys = new Dictionary<string, byte[]>();

        //[PrincipalPermission(SecurityAction.Demand,Role = "ExchangeSessionKey")]
        public bool Connect(byte[] encryptedSessionKey)
        {
            //string serviceCert = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
            //Console.WriteLine(serviceCert);
            string serviceCert = "Manager";

            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Formatter.ParseName(principal.Identity.Name);

            //pronaci sertifikat i uzeti ga iz skladista
            X509Certificate2 certificate = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, serviceCert);

            //treba dekriptovati kljuc sa privatnim kljucem servisa
            byte[] sessionKey = SessionKeyHelper.DecryptSessionKey(certificate, encryptedSessionKey);

            SessionKeyHelper.PrintSessionKey(sessionKey);

            //ovde se sacuvava kljuc koji je klijent generisao i poslao
            UsersSessionKeys[userName] = sessionKey;

            return true;
        }

        //[PrincipalPermission(SecurityAction.Demand, Role = "RunService")]
        public bool StartNewService(string encryptedMessage)
        {
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Manage.Formatter.ParseName(principal.Identity.Name);

            if (Thread.CurrentPrincipal.IsInRole("RunService"))
            {
                string data;
                //treba da se salje niz bajtova
                AES_CBC.DecryptData(encryptedMessage, UsersSessionKeys[userName], out data);
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

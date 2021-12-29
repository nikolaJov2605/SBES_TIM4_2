using CertHelper;
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
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Formatter.ParseName(principal.Identity.Name);

            if (Thread.CurrentPrincipal.IsInRole("ExchangeSessionKey"))
            {
                try
                {
                    NetTcpBinding binding = new NetTcpBinding();
                    binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                    /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
                    X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
                    EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                              new X509CertificateEndpointIdentity(srvCert));
                    using (AuditClient proxy = new AuditClient(binding, addressAudit))
                    {
                        proxy.LogAuthorizationSuccess(userName, OperationContext.Current.IncomingMessageHeaders.Action);
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
                    NetTcpBinding binding = new NetTcpBinding();
                    binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                    /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
                    X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
                    EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                              new X509CertificateEndpointIdentity(srvCert));
                    using (AuditClient proxy = new AuditClient(binding, addressAudit))
                    {
                        proxy.LogAuthorizationFailed(userName, OperationContext.Current.IncomingMessageHeaders.Action, "Connect need ExchangeSessionKey permission");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            //string serviceCert = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
            //Console.WriteLine(serviceCert);
            string serviceCert = "Manager";

            //pronaci sertifikat i uzeti ga iz skladista
            X509Certificate2 certificate = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, serviceCert);

            //treba dekriptovati kljuc sa privatnim kljucem servisa
            byte[] sessionKey = SessionKeyHelper.DecryptSessionKey(certificate, encryptedSessionKey);

            SessionKeyHelper.PrintSessionKey(sessionKey);

            //ovde se sacuvava kljuc koji je klijent generisao i poslao
            UsersSessionKeys[userName] = sessionKey;

            return true;
        }

        [PrincipalPermission(SecurityAction.Demand, Role = "RunService")]
        public bool StartNewService(byte[] encryptedMessage)
        {
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Manage.Formatter.ParseName(principal.Identity.Name);

            string data = AES_CBC.DecryptData(encryptedMessage, UsersSessionKeys[userName]);
            Console.WriteLine(data);

            string protocol = "", port = "";
            int portNumber = 0;
            string[] msgdata = data.Split(',');
            if (msgdata.Length > 2)
            {
                protocol = msgdata[1];
                port = msgdata[2];
                Int32.TryParse(msgdata[2], out portNumber);
            }
            else
            {
                if (Int32.TryParse(msgdata[1], out portNumber))
                {
                    port = msgdata[1];
                }
                else
                {
                    protocol = msgdata[1];
                }
            }
            string[] groups = { string.Empty };

            WindowsIdentity windowsIdentity = (Thread.CurrentPrincipal.Identity as IIdentity) as WindowsIdentity;
            foreach (IdentityReference item in windowsIdentity.Groups)
            {
                //Trazimo SID koji je u jednom zapisu, konvertujemo ga u citljivi sid
                // group Name i trazimo permisije za njega 
                SecurityIdentifier sid = (SecurityIdentifier)item.Translate(typeof(SecurityIdentifier));
                var name = sid.Translate(typeof(NTAccount));
                //Ovaj deo izbrisati jer sam kopirao njihov formatter lakse je i nije tesko razumeti 
                string groupName = Formatter.ParseName(name.ToString());
                if (ResixLoader.GetPermissions(groupName, out string[] permissions))
                {
                    groups[groups.Count() - 1] = groupName;
                }

            }


            //nakon provere black liste
            string reason = string.Empty;
            bool canRun = BlacklistManager.Instance().PermissionGranted(groups,protocol,portNumber, out reason);
            
            try
            {
                NetTcpBinding binding = new NetTcpBinding();
                binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
                X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
                EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                               new X509CertificateEndpointIdentity(srvCert));

                using (AuditClient proxy = new AuditClient(binding, addressAudit))
                {
                    if (canRun)
                    {
                        proxy.LogServiceStarted(userName);
                    }
                    else
                    {
                        proxy.LogServiceStartDenied(userName, protocol, port, reason);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return true;
            //Thread.CurrentPrincipal.IsInRole("PERMISION") se koristi samo kada se proverava bazna perisija kao sto je npr read ili kod nas ExchangeSessionKey 
            //i to samo u CheckAccessCore funkciji
            
            //if (Thread.CurrentPrincipal.IsInRole("RunService"))
            //{
            //    try
            //    {
            //        //Audit.Audit.ServiceStarted(userName);
            //        NetTcpBinding binding = new NetTcpBinding();
            //        binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

            //        /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
            //        X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
            //        EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
            //                                  new X509CertificateEndpointIdentity(srvCert));
            //        using (AuditClient proxy = new AuditClient(binding, addressAudit))
            //        {
            //            proxy.LogAuthorizationSuccess(userName, OperationContext.Current.IncomingMessageHeaders.Action);
            //            proxy.LogServiceStarted(userName);
            //        }
            //    }
            //    catch (Exception e)
            //    {
            //        Console.WriteLine(e.Message);
            //    }
            //}
            //else
            //{
            //    try
            //    {
            //        //Audit.Audit.ServiceStartDenied();
            //        NetTcpBinding binding = new NetTcpBinding();
            //        binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

            //        /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
            //        X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
            //        EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
            //                                  new X509CertificateEndpointIdentity(srvCert));
            //        using (AuditClient proxy = new AuditClient(binding, addressAudit))
            //        {
            //            proxy.LogAuthorizationFailed(userName, OperationContext.Current.IncomingMessageHeaders.Action, "StartNewService need RunService permission");
            //            proxy.LogServiceStartDenied();
            //        }
            //    }
            //    catch (Exception e)
            //    {
            //        Console.WriteLine(e.Message);
            //    }

            //    throw new FaultException("User " + userName +
            //        " tried to start service without RunService role.");
            //}
        }
    }
}

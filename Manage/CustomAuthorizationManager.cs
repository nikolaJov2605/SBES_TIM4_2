using AuditManager;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class CustomAuthorizationManager : ServiceAuthorizationManager
    {
        protected override bool CheckAccessCore(OperationContext operationContext)
        {
            //TO DO : Obezbediti proveru permisije iz principala koji smo podesili na kontekst
            CustomPrincipal principal = operationContext.ServiceSecurityContext.AuthorizationContext.Properties["Principal"] as CustomPrincipal;

            bool retVal = principal.IsInRole("ExchangeSessionKey");

            if(!retVal)
            {
                try
                {
                    //Audit.Audit.AuthorizationFailed(Formatter.ParseName(principal.Identity.Name),
                    //                                OperationContext.Current.IncomingMessageHeaders.Action, "User does't have session key.");
                    NetTcpBinding binding = new NetTcpBinding();
                    binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                    /// Use CertManager class to obtain the certificate based on the "srvCertCN" representing the expected service identity.
                    X509Certificate2 srvCert = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, "Auditer");
                    EndpointAddress addressAudit = new EndpointAddress(new Uri("net.tcp://localhost:9999/Audit"),
                                              new X509CertificateEndpointIdentity(srvCert));
                    using (AuditClient proxy = new AuditClient(binding, addressAudit))
                    {
                        proxy.LogAuthorizationFailed(Formatter.ParseName(principal.Identity.Name),
                                                    OperationContext.Current.IncomingMessageHeaders.Action, "User does't have session key.");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            return retVal;
        }
    }
}

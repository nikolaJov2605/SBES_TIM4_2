using CertHelper;
using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class CustomAuthorizationPolicy : IAuthorizationPolicy
    {
        public CustomAuthorizationPolicy()
        {
            Id = Guid.NewGuid().ToString();
        }


        public ClaimSet Issuer
        {
            get { return ClaimSet.System; }
        }

        public string Id { get; set; }

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            // pokusavamo iz konteksta da izvucemo objekat koji je lista // hint to je neki recnik key string // value
            //objekat koji je lista identiteta
            if(!evaluationContext.Properties.TryGetValue("Identities",out object lista))
            {
                return false;
            }

            IList<IIdentity> identities = lista as IList<IIdentity>;
            // ako je lista null nisto nista dobavili kao vrednost i ako je identities lista == 0 znaci da nema elemenata
            //tj identiteta
            if(lista == null || identities.Count<= 0)
            {
                return false;
            }

            WindowsIdentity windowsIdentity = identities[0] as WindowsIdentity;

            try
            {
                AuditClient.Instance().LogAuthenticationSuccess(Formatter.ParseName(windowsIdentity.Name));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            //ako je sve uredu onda kreiramo u recniku novu vrednost koja ce biti nas custom principall kao principal
            //customPrincipal mozemo kastovati iz Iidentity u WindowsIdentity jer win poseduje iidenty pa zna kako da popuni polja
            evaluationContext.Properties["Principal"] = new CustomPrincipal(windowsIdentity);
            return true;
        }
    }
}

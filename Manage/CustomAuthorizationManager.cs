using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Manage
{
    public class CustomAuthorizationManager : ServiceAuthorizationManager
    {
        
        public override bool CheckAccess(OperationContext operationContext)
        {
            //iz konteksta izvlacimo kontekst autorizacije koji ima recnik koji smo popunjavali sa customAutorPolices
            // kastujemo u bas tog trenutnog identity i proveravamo da li ima permisiju
            // po meni svi treba da mogu da razmene te kljuceve
            CustomPrincipal currentPrincipal = operationContext.ServiceSecurityContext.AuthorizationContext.Properties["Principal"] as CustomPrincipal;
            return currentPrincipal.IsInRole("ExchangeSessionKey");
        }
    }
}

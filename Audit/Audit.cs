using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Audit
{
    public class Audit : IDisposable
    {
        private static EventLog customLog = null;
        const string SourceName = "ServiceManager.Audit";
        const string LogName = "ServiceManagerLogs";

        static Audit()
        {
            try
            {
                if (!EventLog.SourceExists(SourceName))
                {
                    EventLog.CreateEventSource(SourceName, LogName);
                }
                customLog = new EventLog(LogName,Environment.MachineName, SourceName);
            }
            catch (Exception e)
            {
                customLog = null;
                Console.WriteLine("Error while trying to create log handle. Error = {0}", e.Message);
            }
        }

        public static void AuthenticationSuccess(string userName)
        {
            if (customLog != null)
            {
                string UserAuthenticationSuccess = AuditEvents.AuthenticationSuccess;
                string message = String.Format(UserAuthenticationSuccess, userName);
                customLog.WriteEntry(message);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.AuthenticationSuccess));
            }
        }

        public static void AuthorizationSuccess(string userName, string serviceName)
        {
            if (customLog != null)
            {
                string AuthorizationSuccess = AuditEvents.AuthorizationSuccess;
                string message = String.Format(AuthorizationSuccess, userName, serviceName);
                customLog.WriteEntry(message);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.AuthorizationSuccess));
            }
        }

        public static void AuthorizationFailed(string userName, string serviceName, string reason)
        {
            if (customLog != null)
            {
                string AuthorizationFailed = AuditEvents.AuthorizationFailed;
                string message = String.Format(AuthorizationFailed, userName, serviceName, reason);
                customLog.WriteEntry(message, EventLogEntryType.Warning);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.AuthorizationFailure));
            }
        }

        public static void ServiceStarted(string userName)
        {
            if(customLog != null)
            {
                string ServiceStarted = AuditEvents.ServiceStarted;
                string message = String.Format(ServiceStarted, userName);
                customLog.WriteEntry(message);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.ServiceStarted));
            }
        }

        public static void ServiceStartDenied()
        {
            if (customLog != null)
            {
                string ServiceStartDenied = AuditEvents.ServiceStartDenied;
                string message = String.Format(ServiceStartDenied);
                customLog.WriteEntry(message);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.ServiceStartDenied));
            }
        }

        public static void DoSAttackDetected(string userName)
        {
            if (customLog != null)
            {
                string DoSAttackDetected = AuditEvents.DoSAttackDetected;
                string message = String.Format(DoSAttackDetected, userName);
                customLog.WriteEntry(message);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.DoSAttackDetected));
            }
        }

        public void Dispose()
        {
            if (customLog != null)
            {
                customLog.Dispose();
                customLog = null;
            }
        }
    }
}

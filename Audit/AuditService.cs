﻿using Contract;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Audit
{
    public class AuditService : IAuditContract
    {
        private static Dictionary<string, List<Attempt>> unsuccessfulStartAttempts = new Dictionary<string, List<Attempt>>();
        
        public void LogAuthenticationSuccess(string username)
        {
            try
            {
                Audit.AuthenticationSuccess(username);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void LogAuthorizationFailed(string username, string serviceName, string reason)
        {
            try
            {
                Audit.AuthorizationFailed(username, serviceName, reason);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void LogAuthorizationSuccess(string username, string serviceName)
        {
            try
            {
                Audit.AuthorizationSuccess(username, serviceName);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void LogServiceStartDenied(string username, string protocol, string port, string reason)
        {
            try
            {
                Audit.ServiceStartDenied(username, protocol, port);
                Thread t = new Thread(() => CheckForDoS(username, protocol, port, reason));
                t.Start();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void LogServiceStarted(string username)
        {
            try
            {
                Audit.ServiceStarted(username);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void TestCommunication()
        {
            Console.WriteLine("Communication established.");
        }

        private static void CheckForDoS(string username, string protocol, string port, string reason)
        {
            if(!unsuccessfulStartAttempts.ContainsKey(username))
            {
                unsuccessfulStartAttempts[username] = new List<Attempt>();
                Console.WriteLine("ubacen prvi - {0}:{1}",protocol,port);
                unsuccessfulStartAttempts[username].Add(new Attempt(protocol, port, 1, DateTime.Now));
            }
            else
            {
                bool exists = false;
                List<Attempt> elementsToRemove = new List<Attempt>();
                foreach (Attempt attempt in unsuccessfulStartAttempts[username])
                {
                    switch (reason)
                    {
                        case "PROTOCOL":
                            if (attempt.Protocol.Equals(protocol))
                            {
                                Console.WriteLine("check");
                                exists = true;
                                if (attempt.CheckTime(DateTime.Now, Convert.ToInt32(ConfigurationManager.AppSettings["timeBetweenAttempts"])) == false)
                                    elementsToRemove.Add(attempt);
                                else if (attempt.NumberOfAttempt > Convert.ToInt32(ConfigurationManager.AppSettings["numberOfAttempts"]))
                                {
                                    Audit.DoSAttackDetected(username);
                                    break;
                                }
                            }
                            break;

                        case "PORT":
                            if (attempt.Port.Equals(port))
                            {
                                exists = true;
                                if (attempt.CheckTime(DateTime.Now, Convert.ToInt32(ConfigurationManager.AppSettings["timeBetweenAttempts"])) == false)
                                    elementsToRemove.Add(attempt);
                                else if (attempt.NumberOfAttempt > Convert.ToInt32(ConfigurationManager.AppSettings["numberOfAttempts"]))
                                {
                                    Audit.DoSAttackDetected(username);
                                    break;
                                }
                            }
                            break;

                        default:
                            if (attempt.Protocol.Equals(protocol) && attempt.Port.Equals(port))
                            {
                                exists = true;
                                if (attempt.Protocol.Equals(protocol) && attempt.Port.Equals(port))
                                {
                                    if (attempt.CheckTime(DateTime.Now, Convert.ToInt32(ConfigurationManager.AppSettings["timeBetweenAttempts"])) == false)
                                        elementsToRemove.Add(attempt);
                                    else
                                    {
                                        if (attempt.NumberOfAttempt > Convert.ToInt32(ConfigurationManager.AppSettings["numberOfAttempts"]))
                                        {
                                            Audit.DoSAttackDetected(username);
                                            break;
                                        }
                                    }
                                }
                            }
                            break;
                    }
                }

                if (!exists)
                {
                    Console.WriteLine("ubacen novi- {0}:{1}", protocol, port);
                    unsuccessfulStartAttempts[username].Add(new Attempt(protocol, port, 1, DateTime.Now));
                }

                foreach (var attempt in elementsToRemove)
                {
                    unsuccessfulStartAttempts[username].Remove(attempt);
                }

            }
        }

        public void BlacklistFaultedState()
        {
            try
            {
                Audit.BlacklistFaultedState();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}

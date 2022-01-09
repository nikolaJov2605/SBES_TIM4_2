﻿using CertHelper;
using Contract;
using Manage;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
        static BlacklistManager BLM = BlacklistManager.Instance();

        public bool Connect(byte[] encryptedSessionKey)
        {
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Formatter.ParseName(principal.Identity.Name);

            if (Thread.CurrentPrincipal.IsInRole("ExchangeSessionKey"))
            {
                try
                {
                    AuditClient.Instance().LogAuthorizationSuccess(userName, OperationContext.Current.IncomingMessageHeaders.Action);
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
                    AuditClient.Instance().LogAuthorizationFailed(userName, OperationContext.Current.IncomingMessageHeaders.Action, "Connect need ExchangeSessionKey permission");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            string serviceCert = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
            //Console.WriteLine(serviceCert);
            //string serviceCert = "Manager";

            X509Certificate2 certificate = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, serviceCert);
            byte[] sessionKey = SessionKeyHelper.DecryptSessionKey(certificate, encryptedSessionKey);

            //SessionKeyHelper.PrintSessionKey(sessionKey);

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
            bool canRun = BlacklistManager.Instance().PermissionGranted(groups, protocol, portNumber, out reason);

            if (canRun)
            {
                StartClientService(protocol, portNumber);
            }
            
            try
            {
                if (canRun)
                {
                    AuditClient.Instance().LogServiceStarted(userName);
                }
                else
                {
                    AuditClient.Instance().LogServiceStartDenied(userName, protocol, port, reason);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return canRun;
        }

        [PrincipalPermission(SecurityAction.Demand, Role = "Modify")]
        public void RemoveRule(string group, string protocol = "", int port = -1)
        {
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Manage.Formatter.ParseName(principal.Identity.Name);

            if (protocol != "" && port != -1)
                BLM.RemoveRule(group, protocol, port);
            else if (protocol == "" && port != -1)
                BLM.RemoveRule(group, port);
            else if (protocol != "" && port == -1)
                BLM.RemoveRule(group, protocol);

            try
            {
                AuditClient.Instance().BlacklistRuleRemoved(userName, group, protocol, (port == -1) ? "" : port.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        [PrincipalPermission(SecurityAction.Demand, Role = "Modify")]
        public void AddRule(string group, string protocol = "", int port = -1)
        {
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            string userName = Manage.Formatter.ParseName(principal.Identity.Name);

            if (protocol != "" && port != -1)
                BLM.AddRule(group, protocol, port);
            else if (protocol == "" && port != -1)
                BLM.AddRule(group, port);
            else if (protocol != "" && port == -1)
                BLM.AddRule(group, protocol);

            try
            {
                AuditClient.Instance().BlacklistRuleAdded(userName, group, protocol, (port == -1) ? "" : port.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void CheckSumFunction()
        { 
            while (true)
            {
                bool isFileValid = BLM.FileHashValid();

                if (!isFileValid)
                {
                    AuditClient.Instance().BlacklistFaultedState();
                    break;
                }

                Thread.Sleep(10000);
            }

            Console.WriteLine("SM is shuting down...");
            Environment.Exit(0);
        }

        private void StartClientService(string protocol, int port)
        {
            if((protocol == null || protocol == "") || (port < 1024 || port > 65535))
            {
                Console.WriteLine("Bad arguments.");
                return;
            }

            string curentPath = AppContext.BaseDirectory;
            string curentPathB = curentPath.Remove(curentPath.Length - 26);
            string filepath = curentPathB + "\\ClientsService\\bin\\Debug\\ClientsService.exe";
            String param = protocol + " " + port.ToString();

            try
            {
                Process.Start(filepath, param);

            }
            catch(Exception ex)
            {
                Console.WriteLine("Start Service Failed: {0}", ex.Message);
            }

        }
    }
}

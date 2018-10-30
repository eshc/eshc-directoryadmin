using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Net;
using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Rfc2251;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace eshc_diradmin
{
    public class LDAPUtils
    {
        private readonly ILogger logger;
        public Parameters Params;
        public LdapConnection Connection;

        public LDAPUtils()
        {
            logger = new Microsoft.Extensions.Logging.Console.ConsoleLogger("ldap", (x, y) => true, true);
        }

        public class Parameters
        {
            public string Host { get; set; } = "localhost";
            public int Port { get; set; } = 389;
            public string RootDN { get; set; } = "dc=directory,dc=eshc,dc=coop";
            public string ManagerDN { get; set; } = "cn=Manager";
            public string ManagerPW { get; set; } = "";

            public string DN(string subdn)
            {
                return subdn + "," + RootDN;
            }

            public string TrimGroupName(string groupDN)
            {
                if (groupDN.StartsWith("cn="))
                {
                    groupDN = groupDN.Substring("cn=".Length);
                }
                string sfx = ",ou=Groups," + RootDN;
                if (groupDN.EndsWith(sfx))
                {
                    groupDN = groupDN.Substring(0, groupDN.Length - sfx.Length);
                }
                return groupDN;
            }

            public string GroupNameToDN(string groupName)
            {
                return String.Format("cn={0},ou=Groups,{1}", groupName, RootDN);
            }
        }

        public void ValidateParametersAndConnect(Parameters prams)
        {
            Params = prams;

            Connection = new LdapConnection { SecureSocketLayer = false };
            EnsureConnection();
        }

        public void EnsureConnection()
        {
            if (!Connection.Connected)
            {
                Connection.Connect(Params.Host, Params.Port);
                if (!Connection.Connected)
                {
                    throw new System.Exception("Could not connect to the LDAP server at " + Params.Host + ":" + Params.Port);
                }
                Connection.Bind(Params.DN(Params.ManagerDN), Params.ManagerPW);
                if (!Connection.Bound)
                {
                    throw new System.Exception("Could not bind to the LDAP server with username " + Params.DN(Params.ManagerDN));
                }
            }
        }

        static string GetOptAttr(LdapEntry e, string name)
        {
            if (e == null)
            {
                return "";
            }
            var a = e.GetAttribute(name);
            if (a == null)
            {
                return "";
            }
            return a.StringValue ?? "";
        }

        public class MemberInfo
        {
            public string DN;
            public string[] Groups;

            public string FirstName; // cn
            public string Surname; // sn
            public string UID;
            public string DisplayName;
            public string Mail;
            public string Flat; // postalAddress
            public string TelephoneNumber;
            public string Password;

            public int DjangoAccount;

            public static string[] LdapAttrList = {
                "cn", "sn", "uid", "displayName", "mail", "postalAddress", "telephoneNumber", "employeeNumber", "userPassword", "memberOf" };

            public MemberInfo(LdapEntry e, LDAPUtils ldap)
            {
                ldap.logger.LogInformation("Reading user info for " + e.Dn);
                DN = e.Dn;
                FirstName = GetOptAttr(e, "cn");
                Surname = GetOptAttr(e, "sn");
                UID = GetOptAttr(e, "uid");
                DisplayName = GetOptAttr(e, "displayName");
                Mail = GetOptAttr(e, "mail");
                Flat = GetOptAttr(e, "postalAddress");
                TelephoneNumber = GetOptAttr(e, "telephoneNumber");
                Password = GetOptAttr(e, "userPassword");
                if (!Int32.TryParse(GetOptAttr(e, "employeeNumber"), out DjangoAccount))
                {
                    DjangoAccount = -1;
                }
                var memof = e.GetAttribute("memberOf");
                if (memof != null)
                {
                    Groups = memof.StringValueArray;
                }
                else
                {
                    Groups = new string[] { };
                }
            }
        }

        public MemberInfo FetchMemberInfo(ClaimsPrincipal user, HttpContext httpContext)
        {
            var DN = user.FindFirstValue(ClaimTypes.NameIdentifier);
            if (DN == null)
            {
                httpContext.SignOutAsync().Wait();
                return null;
            }
            var Entry = Startup.ldap.Connection.Read(DN, LDAPUtils.MemberInfo.LdapAttrList);
            return new LDAPUtils.MemberInfo(Entry, Startup.ldap);
        }

        public List<MemberInfo> FetchAllMembersInfo()
        {
            var mems = new List<MemberInfo>();
            var entries = Connection.Search(Params.DN("ou=Members"),
                LdapConnection.ScopeOne, "(objectClass=inetOrgPerson)", MemberInfo.LdapAttrList, false);
            foreach (var entry in entries)
            {
                mems.Add(new MemberInfo(entry, this));
            }
            mems.Sort((a,b) => a.Surname.CompareTo(b.Surname));
            return mems;
        }

        /// <summary>
        /// </summary>
        /// <returns>A dictionary of pairs: (ldapName, displayName)</returns>
        public SortedDictionary<string, string> FetchAllGroups()
        {
            var result = new SortedDictionary<string, string>();
            var entries = Connection.Search(Params.DN("ou=Groups"),
                LdapConnection.ScopeOne, "(objectClass=groupOfNames)", new string[] { "description" }, false);
            foreach (var entry in entries)
            {
                string dn = entry.Dn;
                string dsc = GetOptAttr(entry, "description");
                if (dsc.Length < 1)
                    dsc = dn;
                result.Add(dn, dsc);
            }
            return result;
        }

        public struct AuthResult
        {
            public bool ValidCredentrials;
            public bool Active;
            public bool SuperAdmin;
            public string DN;
            public string DisplayName;
        }

        static Regex ldapFieldRegex = new Regex(@"[ a-zA-Z0-9@_-]*");
        public static bool ValidateLDAPField(string field)
        {
            return ldapFieldRegex.IsMatch(field);
        }

        public LdapSearchQueue Search(string @base, int scope, RfcFilter filter, string[] attrs, bool namesOnly = false)
        {
            LdapMessage m = new LdapSearchRequest(@base, scope, filter, attrs,
                LdapSearchConstraints.DerefAlways, 512, 1, namesOnly, null);
            return (LdapSearchQueue)Connection.SendRequest(m, null);
        }

        public AuthResult Authenticate(string username, string password)
        {
            if (!ValidateLDAPField(username))
            {
                logger.LogWarning("Tried LDAP injection: " + username);
                return new AuthResult { ValidCredentrials = false, Active = false };
            }

            RfcFilter query = new RfcFilter();
            var UTF8 = System.Text.Encoding.UTF8;
            query.StartNestedFilter(RfcFilter.And);
            query.AddAttributeValueAssertion(RfcFilter.EqualityMatch, "objectClass", UTF8.GetBytes("inetOrgPerson"));
            query.StartNestedFilter(RfcFilter.Or);
            var usernameBytes = UTF8.GetBytes(username);
            query.AddAttributeValueAssertion(RfcFilter.EqualityMatch, "mailPrimaryAddress", usernameBytes);
            query.AddAttributeValueAssertion(RfcFilter.EqualityMatch, "mail", usernameBytes);
            query.AddAttributeValueAssertion(RfcFilter.EqualityMatch, "uid", usernameBytes);
            query.EndNestedFilter(RfcFilter.Or);
            query.EndNestedFilter(RfcFilter.And);

            var resmq = Search(Params.DN("ou=Members"),
                    LdapConnection.ScopeOne, query, new string[] { "displayName", "memberOf" });

            LdapEntry res = null;
            AuthResult ar = new AuthResult();
            LdapMessage msg;
            while ((msg = resmq.GetResponse()) != null)
            {
                if (msg is LdapSearchResult)
                {
                    LdapEntry r = ((LdapSearchResult)msg).Entry;
                    if (res != null)
                    {
                        logger.LogError("LDAP login returned multiple results: " + username);
                        return new AuthResult { ValidCredentrials = false, Active = false };
                    }
                    res = r;
                    logger.LogInformation("LDAP login found user DN: " + res.Dn);
                }
            }
            if (res == null)
            {
                logger.LogError("LDAP login failed to find account: " + username);
                return new AuthResult { ValidCredentrials = false, Active = false };
            }

            ar.ValidCredentrials = false;
            ar.Active = false;
            ar.SuperAdmin = false;
            ar.DN = res.Dn;
            ar.DisplayName = res.GetAttribute("displayName").StringValue ?? res.Dn;

            // try login
            using (LdapConnection userConn = new LdapConnection { SecureSocketLayer = false })
            {
                userConn.Connect(Params.Host, Params.Port);
                if (!userConn.Connected)
                {
                    throw new System.Exception("Could not connect to the LDAP server at " + Params.Host + ":" + Params.Port);
                }
                try
                {
                    userConn.Bind(ar.DN, password);
                }
                catch (LdapException)
                {
                    logger.LogError("LDAP login: wrong password for account: " + ar.DN);
                    return new AuthResult { ValidCredentrials = false, Active = false };
                }
                if (!userConn.Bound)
                {
                    logger.LogError("LDAP login: could not bind account: " + ar.DN);
                    return new AuthResult { ValidCredentrials = false, Active = false };
                }
            }

            ar.ValidCredentrials = true;

            var groups = res.GetAttribute("memberOf").StringValueArray;
            ar.Active = groups.Contains(Params.DN("cn=AllMembers,ou=Groups"));
            ar.SuperAdmin = groups.Contains(Params.DN("cn=InternetSpecialists,ou=Groups"));

            foreach (var group in groups)
            {
                logger.LogDebug("Group: " + group);
            }

            return ar.Active ? ar : new AuthResult { ValidCredentrials = true, Active = false };
        }

        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        public static string EncodeSSHA(string password)
        {
            byte[] salt = new byte[16];
            rngCsp.GetNonZeroBytes(salt);
            byte[] pwd = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] saltedPwd = pwd.Concat(salt).ToArray();
            byte[] sha = SHA256.Create().ComputeHash(saltedPwd);
            return "{SSHA256}" + Convert.ToBase64String(sha.Concat(salt).ToArray());
        }
    }
}

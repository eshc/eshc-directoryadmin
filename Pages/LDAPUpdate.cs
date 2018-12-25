using System;
using System.Text.RegularExpressions;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Novell.Directory.Ldap;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;

namespace eshc_diradmin.Pages
{
    [IgnoreAntiforgeryToken(Order = 9001)]
    public class LdapUpdateModel : PageModel
    {
        [BindProperty]
        public FormData formData { get; set; }

        public IActionResult OnGet()
        {
            Startup.ldap.EnsureConnection();
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Redirect("/Login");
            }
            var DN = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (DN == null)
            {
                HttpContext.SignOutAsync().Wait();
                return Redirect("/Login");
            }
            return Page();
        }

        public IActionResult OnPost()
        {
            Startup.ldap.EnsureConnection();
            // update details
            if (Startup.migrateSecret.Length < 1)
            {
                ModelState.AddModelError("Secret", "Secret not loaded into the app");
            }
            if (formData.Secret != Startup.migrateSecret)
            {
                ModelState.AddModelError("Secret", "Invalid secret");
            }
            if (!ModelState.IsValid)
            {
                return OnGet();
            }
            Dictionary<int, IntranetUtils.User> iusers = IntranetUtils.GetCurrentUserList(Startup.Configuration);
            List<LDAPUtils.MemberInfo> lusers = Startup.ldap.FetchAllMembersInfo();
            var llut = new Dictionary<int, LDAPUtils.MemberInfo>();

            // fill out any missing django account numbers
            foreach (var mi in lusers)
            {
                if (mi.DjangoAccount <= 0)
                {
                    var q = from i in iusers.Values
                            where string.Equals(i.Username, mi.UID, StringComparison.OrdinalIgnoreCase)
                               || string.Equals(i.Email, mi.Mail, StringComparison.OrdinalIgnoreCase)
                            select i.Id;
                    mi.DjangoAccount = q.SingleOrDefault();
                }
                //Console.WriteLine("Matching user " + mi.UID + " with Django user " + mi.DjangoAccount);
                if (mi.DjangoAccount > 0)
                {
                    llut.Add(mi.DjangoAccount, mi);
                }
            }

            int newUsers = 0, modUsers = 0;

            // update/create user data from intranet in ldap
            foreach (var iu in iusers.Values)
            {
                //Console.WriteLine("Intranet user: <" + iu.Username + ">");
                string ldapPwd = iu.PasswordHash;
                string[] parts = iu.PasswordHash.Split('$');
                if (parts.Length >= 4)
                {
                    string algo = parts[0];
                    string iters = parts[1];
                    string salt = parts[2];
                    string bdk = parts[3].Replace('+', '.').TrimEnd('=');
                    string b64salt = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(salt));
                    ldapPwd = "{PBKDF2-SHA256}" + iters + "$" + b64salt + "$" + bdk;
                }
                string ldapCn = iu.FirstName + " " + iu.LastName;
                if (!llut.ContainsKey(iu.Id))
                {
                    // create entry
                    newUsers++;
                    string dn = Startup.ldap.Params.DN("uid=" + iu.Username + ",ou=Members");
                    var ast = new LdapAttributeSet();
                    ast.Add(new LdapAttribute("objectClass", new string[] {
                        "top", "person", "organizationalPerson", "shadowAccount", "inetOrgPerson", "Nextcloud"}));
                    ast.Add(new LdapAttribute("cn", ldapCn));
                    ast.Add(new LdapAttribute("givenName", iu.FirstName));
                    ast.Add(new LdapAttribute("sn", iu.LastName));
                    ast.Add(new LdapAttribute("uid", iu.Username));
                    ast.Add(new LdapAttribute("displayName", iu.PreferredName));
                    ast.Add(new LdapAttribute("employeeNumber", iu.Id.ToString()));
                    ast.Add(new LdapAttribute("mail", iu.Email));
                    ast.Add(new LdapAttribute("NextcloudQuota", "1GB"));
                    ast.Add(new LdapAttribute("postalAddress", iu.PermanentAddress));
                    ast.Add(new LdapAttribute("roomNumber", iu.Room));
                    ast.Add(new LdapAttribute("telephoneNumber", "0" /*iu.PhoneNumber*/));
                    ast.Add(new LdapAttribute("userPassword", ldapPwd));
                    try
                    {
                        LdapEntry e = new LdapEntry(dn, ast);
                        // update ldap db
                        Startup.ldap.Connection.Add(e);
                        // update model
                        var nmi = new LDAPUtils.MemberInfo(e, Startup.ldap);
                        lusers.Add(nmi);
                        llut.Add(nmi.DjangoAccount, nmi); // */
                    }
                    catch (LdapException)
                    {
                        Console.WriteLine("Invalid LDAP conversion for " + iu.Username);
                    }
                }
                else
                {
                    // update entry
                    var lu = llut[iu.Id];
                    List<LdapModification> modifications = new List<LdapModification>();
                    if (ldapCn != lu.FullName)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("cn", ldapCn)));
                    }
                    if (iu.FirstName != lu.FirstName)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("givenName", iu.FirstName)));
                    }
                    if (iu.LastName != lu.Surname)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("sn", iu.LastName)));
                    }
                    if (iu.PreferredName != lu.DisplayName)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("displayName", iu.PreferredName)));
                    }
                    if (iu.Email != lu.Mail)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("mail", iu.Email)));
                    }
                    if (iu.Room != lu.Flat)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("roomNumber", iu.Room)));
                    }
                    if (iu.PermanentAddress != lu.Address)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("postalAddress", iu.PermanentAddress)));
                    }
                    if ("0" != lu.TelephoneNumber)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("telephoneNumber", "0")));
                    }
                    if (ldapPwd != lu.Password)
                    {
                        modifications.Add(new LdapModification(LdapModification.Replace,
                            new LdapAttribute("userPassword", ldapPwd)));
                    }
                    if (modifications.Count < 1)
                    {
                        continue;
                    }
                    modUsers++;
                    try
                    {
                        Startup.ldap.Connection.Modify(lu.DN, modifications.ToArray());
                    }
                    catch (LdapException)
                    {
                        Console.WriteLine("Invalid LDAP conversion for " + lu.DN);
                    }
                }
            }

            // move old users (TODO)

            Console.WriteLine("Users: new: {0} modified: {1}", newUsers, modUsers);

            return Page();
        }

        public class FormData
        {
            [Display(Name = "Secret key")]
            [Required, DataType(DataType.Password)]
            public string Secret { get; set; }
        }
    }
}

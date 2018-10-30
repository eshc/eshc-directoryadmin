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
    public class SuperadminModel : PageModel
    {
        [BindProperty]
        public NewDetails newDetails { get; set; }

        public SortedDictionary<string, string> AllGroups;
        public List<LDAPUtils.MemberInfo> AllInfo;

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
            if (!bool.Parse(User.FindFirstValue("SuperAdmin")))
            {
                return Redirect("/Login");
            }
            AllInfo = Startup.ldap.FetchAllMembersInfo();
            AllGroups = Startup.ldap.FetchAllGroups();
            newDetails = new NewDetails();
            return Page();
        }

        public IActionResult OnPost()
        {
            Startup.ldap.EnsureConnection();
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return RedirectToPage("Login");
            }
            var DN = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (DN == null)
            {
                HttpContext.SignOutAsync().Wait();
                return RedirectToPage("Login");
            }
            if (!bool.Parse(User.FindFirstValue("SuperAdmin")))
            {
                return Redirect("/Login");
            }
            AllInfo = Startup.ldap.FetchAllMembersInfo();
            AllGroups = Startup.ldap.FetchAllGroups();
            // update details
            if (newDetails.membershipMatrix.Count != AllGroups.Count)
            {
                ModelState.AddModelError("", "Group count has changed");
            }
            if (newDetails.membershipMatrix.FirstOrDefault().Count != AllInfo.Count)
            {
                ModelState.AddModelError("", "Member count has changed");
            }
            if (!ModelState.IsValid)
            {
                return Page();
            }

            for (int i = 0; i < AllGroups.Count; i++)
            {
                string GroupDN = AllGroups.ElementAt(i).Key;
                LdapEntry GroupE = Startup.ldap.Connection.Read(GroupDN);
                var Members = new List<string>();
                for (int m = 0; m < AllInfo.Count; m++)
                {
                    if (newDetails.membershipMatrix[i][m])
                    {
                        Members.Add(AllInfo[m].DN);
                    }
                }
                LdapModification Mod = new LdapModification(LdapModification.Replace, new LdapAttribute("member", Members.ToArray()));
                try
                {
                    Startup.ldap.Connection.Modify(GroupDN, Mod);
                }
                catch (Exception)
                {
                    ModelState.AddModelError("", "Failed to update group " + GroupDN);
                }
            }

            return Page();
        }

        public class NewDetails
        {
            public NewDetails()
            {
                var AllInfo = Startup.ldap.FetchAllMembersInfo();
                var AllGroups = Startup.ldap.FetchAllGroups();
                membershipMatrix = new List<List<bool>>(AllGroups.Count);
                foreach (var grp in AllGroups)
                {
                    List<bool> users = new List<bool>(AllInfo.Count);
                    foreach (var user in AllInfo)
                    {
                        users.Add(user.Groups.Contains(grp.Key));
                    }
                    membershipMatrix.Add(users);
                }
            }

            // [group][user]
            [Required]
            public List<List<bool>> membershipMatrix { get; set; }
        }
    }
}

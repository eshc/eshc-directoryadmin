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
            newDetails.membershipMatrix = new List<List<bool>>(AllGroups.Count);
            foreach (var grp in AllGroups)
            {
                List<bool> users = new List<bool>(AllInfo.Count);
                foreach (var user in AllInfo)
                {
                    users.Add(user.Groups.Contains(grp.Key));
                }
                newDetails.membershipMatrix.Add(users);
            }
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
            // update details
            if (!ModelState.IsValid)
            {
                return Page();
            }
            return RedirectToPage("Index");
        }

        public class NewDetails
        {
            // [group][user]
            [Required]
            public List<List<bool>> membershipMatrix { get; set; }
        }
    }
}

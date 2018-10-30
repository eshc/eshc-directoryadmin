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
    public class EditMyDetailsModel : PageModel
    {
        [BindProperty]
        public NewDetails newDetails { get; set; }

        public LDAPUtils.MemberInfo MyInfo;

        public void OnGet()
        {
            Startup.ldap.EnsureConnection();
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return;
            }
            var DN = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (DN == null)
            {
                HttpContext.SignOutAsync().Wait();
                return;
            }
            MyInfo = Startup.ldap.FetchMemberInfo(User, HttpContext);
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
            MyInfo = Startup.ldap.FetchMemberInfo(User, HttpContext);
            if (MyInfo == null)
            {
                return RedirectToPage("Login");
            }
            // update details
            if (!ModelState.IsValid)
            {
                return Page();
            }
            UpdateDetails();
            return RedirectToPage("Index");
        }

        void UpdateDetails()
        {
            List<LdapModification> modifications = new List<LdapModification>();
            if (newDetails.PreferredName != MyInfo.DisplayName)
            {
                modifications.Add(new LdapModification(LdapModification.Replace,
                    new LdapAttribute("displayName", newDetails.PreferredName)));
            }
            if (newDetails.FirstName != MyInfo.FirstName)
            {
                modifications.Add(new LdapModification(LdapModification.Replace,
                    new LdapAttribute("cn", newDetails.FirstName)));
            }
            if (newDetails.Surname != MyInfo.Surname)
            {
                modifications.Add(new LdapModification(LdapModification.Replace,
                    new LdapAttribute("sn", newDetails.Surname)));
            }
            if (newDetails.Mail != MyInfo.Mail)
            {
                modifications.Add(new LdapModification(LdapModification.Replace,
                    new LdapAttribute("mail", newDetails.Mail)));
            }
            if (newDetails.Flat != MyInfo.Flat)
            {
                modifications.Add(new LdapModification(LdapModification.Replace,
                    new LdapAttribute("postalAddress", newDetails.Flat)));
            }
            if (newDetails.TelephoneNumber != MyInfo.TelephoneNumber)
            {
                modifications.Add(new LdapModification(LdapModification.Replace,
                    new LdapAttribute("telephoneNumber", newDetails.TelephoneNumber)));
            }
            if (modifications.Count < 1)
            {
                return;
            }
            Startup.ldap.Connection.Modify(User.FindFirstValue(ClaimTypes.NameIdentifier),
                modifications.ToArray());
        }

        public class NewDetails
        {
            [Display(Name = "Preferred name")]
            [Required]
            public string PreferredName { get; set; }

            [Display(Name = "First name(s)")]
            [Required]
            public string FirstName { get; set; }

            [Display(Name = "Surname")]
            [Required]
            public string Surname { get; set; }

            [Display(Name = "E-mail address")]
            [Required, DataType(DataType.EmailAddress)]
            public string Mail { get; set; }

            [Display(Name = "Permanent address")]
            [Required]
            public string Flat { get; set; }

            [Display(Name = "Telephone number")]
            public string TelephoneNumber { get; set; }
        }
    }
}

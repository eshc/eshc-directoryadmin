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
    public class ChangePwdModel : PageModel
    {
        [BindProperty]
        public PassData passData { get; set; }

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
            if (passData.NewPassword != passData.RepeatedPassword)
            {
                ModelState.AddModelError("RepeatedPassword", "Repeated password must be the same as old password");
            }
            var oldAuth = Startup.ldap.Authenticate(MyInfo.UID, passData.OldPassword);
            if (!oldAuth.ValidCredentrials)
            {
                ModelState.AddModelError("OldPassword", "You need to enter your valid current password");
            }
            if (!ModelState.IsValid || ModelState.ErrorCount > 0)
            {
                return Page();
            }

            UpdatePassword();
            HttpContext.SignOutAsync().Wait();
            return RedirectToPage("Login");
        }

        void UpdatePassword()
        {
            string ldapPwd = LDAPUtils.EncodeSSHA(passData.NewPassword);
            var pwdMod = new LdapModification(LdapModification.Replace,
                    new LdapAttribute("userPassword", ldapPwd));
            Startup.ldap.Connection.Modify(User.FindFirstValue(ClaimTypes.NameIdentifier),
                pwdMod);
        }

        public class PassData
        {
            [Display(Name = "Old password")]
            [Required, DataType(DataType.Password)]
            public string OldPassword { get; set; }

            [Display(Name = "New password")]
            [Required, DataType(DataType.Password)]
            [MinLength(8)]
            public string NewPassword { get; set; }

            [Display(Name = "Repeated password")]
            [Required, DataType(DataType.Password)]
            public string RepeatedPassword { get; set; }
        }
    }
}

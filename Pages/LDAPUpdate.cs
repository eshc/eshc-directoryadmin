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

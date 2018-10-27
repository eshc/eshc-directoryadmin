using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace eshc_diradmin.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public LoginData loginData { get; set; }

        public LDAPUtils.AuthResult Result;

        public async Task<IActionResult> OnPostAsync()
        {
            Startup.ldap.EnsureConnection();
            if (ModelState.IsValid)
            {
                Result = Startup.ldap.Authenticate(loginData.Username, loginData.Password);
                if (!Result.ValidCredentrials)
                {
                    ModelState.AddModelError("", "Username or password is invalid");
                    return Page();
                }
                if (!Result.Active)
                {
                    ModelState.AddModelError("", "Your account hasn't been verified by an administrator yet");
                    return Page();
                }
                var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, Result.DN));
                identity.AddClaim(new Claim(ClaimTypes.Name, Result.DisplayName));
                identity.AddClaim(new Claim("SuperAdmin", Result.SuperAdmin.ToString()));
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal,
                    new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTime.UtcNow.AddMinutes(20) });
                return RedirectToPage("Index");
            }
            else
            {
                ModelState.AddModelError("", "Username or password is blank");
                return Page();
            }
        }

        public class LoginData
        {
            [Required]
            public string Username { get; set; }

            [Required, DataType(DataType.Password)]
            public string Password { get; set; }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;

namespace eshc_diradmin.Pages
{
    public class IndexModel : PageModel
    {
        public LDAPUtils.MemberInfo MyInfo;

        public void OnGet()
        {
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
            var Entry = Startup.ldap.Connection.Read(DN, new string[] { "*", "memberOf" });
            MyInfo = new LDAPUtils.MemberInfo(Entry, Startup.ldap);
        }
    }
}

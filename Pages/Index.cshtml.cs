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
            Startup.ldap.EnsureConnection();
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return;
            }
            var mi = Startup.ldap.FetchMemberInfo(User, HttpContext);
            if (mi.HasValue)
            {
                MyInfo = mi.Value;
            }
        }
    }
}

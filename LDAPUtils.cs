using Novell.Directory.Ldap;

namespace eshc_diradmin
{
    public class LDAPUtils
    {
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
        }

        public static void ValidateParameters(Parameters p)
        {
            using (var Connection = new LdapConnection { SecureSocketLayer = false })
            {
                Connection.Connect(p.Host, p.Port);
                if (!Connection.Connected)
                {
                    throw new System.Exception("Could not connect to the LDAP server at " + p.Host + ":" + p.Port);
                }
                Connection.Bind(p.DN(p.ManagerDN), p.ManagerPW);
                if (!Connection.Bound)
                {
                    throw new System.Exception("Could not bind to the LDAP server with username " + p.DN(p.ManagerDN));
                }
            }
        }
    }
}
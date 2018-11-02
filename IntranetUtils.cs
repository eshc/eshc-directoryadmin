using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Net;
using Npgsql;
using NpgsqlTypes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace eshc_diradmin
{
    public class IntranetUtils
    {
        private static readonly ILogger logger = new Microsoft.Extensions.Logging.Console.ConsoleLogger("intranetpgsql", (x, y) => true, true);

        public static Dictionary<int, User> GetCurrentUserList(IConfiguration cfg)
        {
            var users = new Dictionary<int, User>();
            var dbpar = cfg.GetSection("IntranetDB").Get<Parameters>();
            using (var conn = new NpgsqlConnection(dbpar.ConnectionStr))
            {
                conn.Open();

                using (var cmd = new NpgsqlCommand())
                {
                    cmd.Connection = conn;
                    cmd.CommandText = "SELECT id,username,password,first_name,last_name,email FROM public.auth_user;";
                    using (var r = cmd.ExecuteReader())
                        while (r.Read())
                        {
                            users.Add(r.GetInt32(0), new User
                            {
                                Id = r.GetInt32(0),
                                Username = r.GetString(1),
                                PasswordHash = r.GetString(2),
                                FirstName = r.GetString(3),
                                LastName = r.GetString(4),
                                Email = r.GetString(5),
                                PermanentAddress = "<ERROR>",
                                PhoneNumber = "<ERROR>",
                                FinanceRefNumber = "<ERROR>",
                                ShareReceived = false
                            });
                        }
                }

                using (var cmd = new NpgsqlCommand())
                {
                    cmd.Connection = conn;
                    cmd.CommandText = "SELECT user_id,perm_address,phone_number,ref_number,share_received,preferred_name FROM public.users_profile;";
                    using (var r = cmd.ExecuteReader())
                        while (r.Read())
                        {
                            User u;
                            if (!users.TryGetValue(r.GetInt32(0), out u))
                            {
                                logger.LogWarning("Could not find user data for id " + r.GetInt32(0));
                                continue;
                            }
                            u.PermanentAddress = r.GetString(1);
                            u.PhoneNumber = r.GetString(2);
                            u.FinanceRefNumber = r.GetString(3);
                            u.ShareReceived = r.GetBoolean(4);
                            u.PreferredName = r.GetString(5);
                            if (u.PreferredName.Length < 1)
                            {
                                u.PreferredName = u.FirstName;
                            }
                        }
                }
            }
            return users.Select(p => p.Value).Where(u => u.ShareReceived).ToDictionary(u => u.Id);
        }

        public class Parameters
        {
            /// <summary>
            /// PostgreSQL database connection string used to gain access to Django's database.
            /// </summary>
            public string ConnectionStr { get; set; }
        }

        /// <summary>
        /// Model of a Django user
        /// </summary>
        public class User
        {
            // common
            public int Id { get; set; }
            // auth_user
            public string Username { get; set; }
            public string PasswordHash { get; set; }
            public string FirstName { get; set; }
            public string LastName { get; set; }
            public string Email { get; set; }
            // users_profile
            public string PreferredName { get; set; }
            public string PermanentAddress { get; set; }
            public string PhoneNumber { get; set; }
            public string FinanceRefNumber { get; set; }
            public bool ShareReceived { get; set; }
        }
    }
}

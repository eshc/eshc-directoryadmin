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
        private readonly ILogger logger;
        public Parameters Params;
        public NpgsqlConnection Connection;

        /// <summary>
        /// Connects to the database using parameters loaded from settings.
        /// </summary>
        public IntranetUtils(IConfiguration cfg)
        {
            logger = new Microsoft.Extensions.Logging.Console.ConsoleLogger("intranetpgsql", (x, y) => true, true);
            Params = cfg.GetSection("IntranetDB").Get<Parameters>();
            Connection = new NpgsqlConnection(Params.ConnectionStr);
        }

        public class Parameters
        {
            /// <summary>
            /// PostgreSQL database connection string used to gain access to Django's database.
            /// </summary>
            public string ConnectionStr { get; set; }
        }
    }
}

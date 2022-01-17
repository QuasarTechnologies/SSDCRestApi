using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;



/// <summary>
/// Designed by AnaSoft Inc. 2019
/// http://www.anasoft.net/apincore 
/// 
///  
/// NOTE:
/// Select authentication type IS4 in API project appsettings.json
/// Authentication:UseIdentityServer4 = True
/// Get client settings and tests for IS4 connectivity in http://www.anasoft.net/apincore
/// </summary>

namespace IdentityServer
{
    public class Startup
    {

        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }


        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {

            //identity server 4 cert
            //var cert = new X509Certificate2(Path.Combine(Environment.ContentRootPath, "idsrv4.pfx"), "your_cert_password");


            services.AddMvc(option => option.EnableEndpointRouting = false)
                 .AddNewtonsoftJson();

            //add identity server 4
            services.AddIdentityServer()
            //.AddSigningCredential(cert)
            .AddDeveloperSigningCredential()
            .AddInMemoryApiResources(Config.GetApiResources())
            .AddInMemoryClients(Config.GetClients())
            .AddInMemoryApiScopes(Config.GetApiScopes())
             .AddProfileService<ProfileService>();
            //.AddTestUsers(Config.GetTestUsers()); 

            //initiate users' list
            List<User> users = Config.Users;

            //IS4 service DI
            services.AddTransient<IResourceOwnerPasswordValidator, ResourceOwnerPasswordValidator>(); // Adds the IdentityServer4 interface to customize the process of authentication
            services.AddTransient<IProfileService, ProfileService>(); // Adds the IdentityServer4 interface to customize the process of getting the claims.


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (Environment.EnvironmentName == "Development")
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler(builder =>
                {
                    builder.Run(async context =>
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                        context.Response.ContentType = "text/html";
                        var ex = context.Features.Get<IExceptionHandlerFeature>();
                        if (ex != null)
                        {
                            var err = $"<h1>Error: {ex.Error.Message}</h1>{ex.Error.StackTrace}";
                            context.Response.Headers.Add("application-error", ex.Error.Message);
                            context.Response.Headers.Add("access-control-expose-headers", "application-error");
                            context.Response.Headers.Add("access-control-allow-origin", "*");
                            await context.Response.WriteAsync(err).ConfigureAwait(false);
                        }
                    });
                });// this will add the global exception handle for production evironment.
            }

            app.UseIdentityServer(); //add the IdentityServer
            app.UseMvc();


            //IS4 start page
            string apiResources = "<div><hr>Registered ApiResouces:<ul>";
            List<IdentityServer4.Models.ApiResource> apires = Config.GetApiResources().ToList();
            foreach (IdentityServer4.Models.ApiResource ar in apires)
            {
                apiResources += "<li>" + ar.Name + "</li>";
            }
            apiResources += "</ul></div>";

            string scopes = String.Empty;
            string clients = "<div><hr>Registered Clients:<ul>";
            List<IdentityServer4.Models.Client> clies = Config.GetClients().ToList();
            foreach (IdentityServer4.Models.Client cl in clies)
            {
                scopes = String.Join(",", cl.AllowedScopes);
                clients += "<li>" + cl.ClientId + "(scopes:" + scopes + ")</li>";
            }
            clients += "</ul></div>";


            app.Run(async (context) =>
            {
                await context.Response.WriteHtmlAsync(@"
                     <html><head><link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css' integrity='sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb' crossorigin='anonymous'><link rel='stylesheet' href='https://use.fontawesome.com/releases/v5.3.1/css/all.css' integrity='sha384-mzrmE5qonljUremFsqc01SB46JvROS7bZs3IO2EmfFsd15uHvIt+Y8vEf7N7fWAU' crossorigin='anonymous'></head><body>
                     <div class='jumbotron'>    
                        <img class='thumbnail img-responsive' src='https://identityserver4.readthedocs.io/en/latest/_images/logo.png' />
                        <h3>IdentityServer service is running!</h3>
                        Supported by IdentityServer4. <br/>IdentityServer4 is an OpenID Connect and OAuth 2.0 framework for ASP.NET Core.
                    </div>" +
                    apiResources + clients +
                    @"
					<hr><a href='/.well-known/openid-configuration'>Get IS4 configuration</a>                    					
					<hr><a href='https://identityserver4.readthedocs.io/en/latest/'>Documentation</a> 
                    </body></html>
                    ");
            });



        }
    }
}

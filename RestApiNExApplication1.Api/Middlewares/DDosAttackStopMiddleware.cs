using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RestApiNExApplication1.Api.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;


//Warning! If you have a Load Balancer, then you must to configure the Load Balancer to send 
//         the original Client's IP as the Request IP to the webserver. Another option is to pass the 
//         original Client IP in a X-Forwarded-For header. 
//         RequestHandler maintains its counters using the Client IP. If the Client IP is the Load Balancer's IP, 
//         not the original Client's IP, then it will lock out the load balancer, causing total 
//         outage on your website.
//https://docs.microsoft.com/en-us/aspnet/core/migration/http-modules?view=aspnetcore-5.0


namespace RestApiNExApplication1.Api.Middlewares
{
    public class DDosAttackStopMiddleware
    {
        private readonly RequestDelegate _next;

        private readonly DDosAttackMonitoringService _DDosAttackMonitoringService;

        private const string XForwardedForHeader = "X-Forwarded-For";

        public DDosAttackStopMiddleware(RequestDelegate next, DDosAttackMonitoringService dDosAttackMonitoringService)
        {
            _next = next;
            _DDosAttackMonitoringService = dDosAttackMonitoringService;
        }

        public async Task Invoke(HttpContext context)
        {
            // Before request processing.

            //DDosAttackMonitoringService
            if (_DDosAttackMonitoringService.Enabled)
            {

                if (IsPathDDosAttackMonitored(context))  //check if api match attributed method
                {
                    var ipAddress = context.Request.HttpContext.Connection.RemoteIpAddress.MapToIPv4();
                    if (context.Request.Headers.ContainsKey(XForwardedForHeader))  //load balancers passing the original client IP
                        ipAddress = IPAddress.Parse(context.Request.Headers[XForwardedForHeader]).MapToIPv4();

                    var terminateRequest = await _DDosAttackMonitoringService.IsDDosAttack(ipAddress);
                    if (terminateRequest)
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                        await context.Response.WriteAsync("TooManyHits");
                    }
                    else
                        await _next.Invoke(context);
                }
                else
                    await _next.Invoke(context);
            }
            else
                await _next.Invoke(context);

            // Clean up.
        }


        private bool IsPathDDosAttackMonitored(HttpContext context)
        {
            if (!context.Request.Path.HasValue) return false;
            if (_DDosAttackMonitoringService.FullServiceLevelProtection) return true;

            var reqPath = context.Request.Path.ToString().ToLower();
            var reqMethod = context.Request.Method.ToString().ToUpper();

            reqPath = reqPath.Replace(@"\", "/");
            reqPath = reqPath.Substring(reqPath.IndexOf("api/") + 4);
            string reqMethodPath = reqMethod + " " + reqPath;

            //NOTE: protection at HTTP Controller/method level 
            foreach (string httpMethodController in _DDosAttackMonitoringService.ProtectedCalls)
            {
                if (reqMethodPath.Contains(httpMethodController)) return true;
            }

            return false;

        }

        //private string GetClientIP(HttpContext context)
        //{
        //    string ipList = context.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

        //    if (!string.IsNullOrEmpty(ipList))
        //    {
        //        return ipList.Split(',')[0];
        //    }

        //    return request.ServerVariables["REMOTE_ADDR"];
        //}

    }

    public static class DDosAttackStopMiddlewareExtensions
    {
        public static IApplicationBuilder UseDDosAttackStopMiddlewareExtensions(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<DDosAttackStopMiddleware>();
        }
    }



}


using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace RestApiNExApplication1.Api.Middlewares
{
    /// <summary>
    /// NOTE: this pipeline is only used when integration tests run to populate empty 
    ///       requests RemoteIp address required for DDoS attacks prevention test
    /// </summary>
    public class FakeRemoteIpAddressMiddleware
    {
        private readonly RequestDelegate next;
        private IPAddress fakeIpAddress = null; // IPAddress.Parse("127.168.1.32");

        public FakeRemoteIpAddressMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        //RemoteIpAddress=null when run from Integration test so must be set fake one for DDoS attacks prevention tests
        public async Task Invoke(HttpContext httpContext)
        {
            if (fakeIpAddress == null)
                fakeIpAddress = IPAddress.Parse("127.168.1." + RandomNumber(1, 168));
            httpContext.Connection.RemoteIpAddress = fakeIpAddress;

            await this.next(httpContext);
        }

        // Generates a random number within a range.      
        public int RandomNumber(int min, int max)
        {
            return (new Random()).Next(min, max);
        }

    }

    public static class FakeRemoteIpAddressMiddlewareExtensions
    {
        public static IApplicationBuilder UseFakeRemoteIpAddressMiddlewareExtensions(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<FakeRemoteIpAddressMiddleware>();
        }
    }

}

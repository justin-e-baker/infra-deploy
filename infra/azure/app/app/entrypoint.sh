using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http.Extensions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// === Force HTTPS ===
app.UseHttpsRedirection();

// === Get ENCLAVE_REDIRECTOR ===
var enclave_redir = Environment.GetEnvironmentVariable("ENCLAVE_REDIRECTOR")
              ?? throw new InvalidOperationException("ENCLAVE_REDIRECTOR not set");

// === Reuse HttpClient ===
using var client = new HttpClient(new HttpClientHandler
{
    AllowAutoRedirect = false
    // Uncomment for self-signed enclave redirector cert (prob never needed):
    // ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});

// === PROXY ALL PATHS ===
app.Map("/{**path}", async context =>
{
    var request = context.Request;

    // Build upstream URL
    var targetUri = new UriBuilder("https", enclave_redir)
    {
        Path  = request.Path.Value ?? "/",
        Query = request.QueryString.Value ?? ""
    }.Uri;

    var proxyRequest = new HttpRequestMessage
    {
        Method     = new HttpMethod(request.Method),
        RequestUri = targetUri
    };

    // === Copy request headers (skip Host) ===
    foreach (var header in request.Headers)
    {
        if (string.Equals(header.Key, "Host", StringComparison.OrdinalIgnoreCase)) continue;
        if (string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase)) continue;

        var values = header.Value.ToArray();
        if (proxyRequest.Headers.TryAddWithoutValidation(header.Key, values)) continue;
        if (proxyRequest.Content != null)
            proxyRequest.Content.Headers.TryAddWithoutValidation(header.Key, values);
    }

    // === Copy body for POST/PUT/PATCH ===
    if (HttpMethods.IsPost(request.Method) || 
        HttpMethods.IsPut(request.Method) || 
        HttpMethods.IsPatch(request.Method))
    {
        proxyRequest.Content = new StreamContent(request.Body);
        if (!string.IsNullOrEmpty(request.ContentType))
            proxyRequest.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(request.ContentType);
    }

    // === Send to ENCLAVE_REDIRECTOR ===
    var response = await client.SendAsync(proxyRequest, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

    // === STRIP ALL UPSTREAM HEADERS ===
    context.Response.Headers.Clear();

    // === SET SAFE, REALISTIC HEADERS ===
    context.Response.StatusCode = (int)response.StatusCode;

    // Content headers (required for body)
    if (response.Content.Headers.ContentType != null)
        context.Response.Headers["Content-Type"] = response.Content.Headers.ContentType.ToString();
    if (response.Content.Headers.ContentLength.HasValue)
        context.Response.ContentLength = response.Content.Headers.ContentLength.Value;

    // === FAKE REALISTIC HEADERS (100% OPTIONAL) ===
    context.Response.Headers["Server"] = "Kestrel";
    context.Response.Headers["Date"] = DateTimeOffset.UtcNow.ToString("R");
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    context.Response.Headers["Pragma"] = "no-cache";
    context.Response.Headers["Expires"] = "0";
    context.Response.Headers["Access-Control-Allow-Origin"] = "*";
    context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";

    // === STREAM BODY ===
    await response.Content.CopyToAsync(context.Response.Body);
});

// === Run ===
app.Run();
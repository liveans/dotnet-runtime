// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using System.Net.Test.Common;
using System.Net.Quic;
using TestUtilities;
using Microsoft.DotNet.XUnitExtensions;
using System.Threading;

namespace System.Net.Http.Functional.Tests
{
    public abstract class HttpClientHandler_AltSvc_Test : HttpClientHandlerTestBase
    {
        public HttpClientHandler_AltSvc_Test(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>
        /// HTTP/3 tests by default use prenegotiated HTTP/3. To test Alt-Svc upgrades, that must be disabled.
        /// </summary>
        private HttpClient CreateHttpClient(Version version)
        {
            var client = CreateHttpClient();
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
            client.DefaultRequestVersion = version;
            return client;
        }

        [Theory]
        [MemberData(nameof(AltSvcHeaderUpgradeVersions))]
        public async Task AltSvc_Header_Upgrade_Success(Version fromVersion, bool overrideHost)
        {
            AsyncLocal<object> asyncLocal = new();
            asyncLocal.Value = new();

            TestEventListener? listener = null;
            if (UseVersion == HttpVersion30)
            {
                listener = new TestEventListener(e =>
                {
                    if (asyncLocal.Value is not null)
                    {
                        lock (_output)
                        {
                            _output.WriteLine($"[AltSvc_Header_Upgrade_Success]{e}");
                        }
                    }
                }, TestEventListener.NetworkingEvents);
            }
            // The test makes a request to a HTTP/1 or HTTP/2 server first, which supplies an Alt-Svc header pointing to the second server.
            using GenericLoopbackServer firstServer =
                fromVersion.Major switch
                {
                    1 => Http11LoopbackServerFactory.Singleton.CreateServer(new LoopbackServer.Options { UseSsl = true }),
                    2 => Http2LoopbackServer.CreateServer(),
                    _ => throw new Exception("Unknown HTTP version.")
                };

            // The second request is expected to come in on this HTTP/3 server.
            using Http3LoopbackServer secondServer = CreateHttp3LoopbackServer();

            if (!overrideHost)
                Assert.Equal(firstServer.Address.IdnHost, secondServer.Address.IdnHost);

            using HttpClient client = CreateHttpClient(fromVersion);

            Task<HttpResponseMessage> firstResponseTask = client.GetAsync(firstServer.Address);
            Task serverTask = firstServer.AcceptConnectionSendResponseAndCloseAsync(additionalHeaders: new[]
            {
                new HttpHeaderData("Alt-Svc", $"h3=\"{(overrideHost ? secondServer.Address.IdnHost : null)}:{secondServer.Address.Port}\"")
            });

            await new[] { firstResponseTask, serverTask }.WhenAllOrAnyFailed(30_000).ConfigureAwait(false);

            using HttpResponseMessage firstResponse = firstResponseTask.Result;
            Assert.True(firstResponse.IsSuccessStatusCode);

            await AltSvc_Upgrade_Success(firstServer, secondServer, client).ConfigureAwait(false);
            listener?.Dispose();
        }

        public static TheoryData<Version, bool> AltSvcHeaderUpgradeVersions =>
            new TheoryData<Version, bool>
            {
                { HttpVersion.Version11, true },
                { HttpVersion.Version11, false },
                { HttpVersion.Version20, true },
                { HttpVersion.Version20, false }
            };

        [Fact]
        public async Task AltSvc_ConnectionFrame_UpgradeFrom20_Success()
        {
            AsyncLocal<object> asyncLocal = new();
            asyncLocal.Value = new();

            TestEventListener? listener = null;
            if (UseVersion == HttpVersion30)
            {
                listener = new TestEventListener(e =>
                {
                    if (asyncLocal.Value is not null)
                    {
                        lock (_output)
                        {
                            _output.WriteLine($"[AltSvc_ConnectionFrame_UpgradeFrom20_Success]{e}");
                        }
                    }
                }, TestEventListener.NetworkingEvents);
            }
            using Http2LoopbackServer firstServer = Http2LoopbackServer.CreateServer();
            using Http3LoopbackServer secondServer = CreateHttp3LoopbackServer(options: new() { TestOutputHelper = _output });
            using HttpClient client = CreateHttpClient(HttpVersion.Version20);

            Task<HttpResponseMessage> firstResponseTask = client.GetAsync(firstServer.Address);
            Task serverTask = Task.Run(async () =>
            {
                await using Http2LoopbackConnection connection = await firstServer.EstablishConnectionAsync().ConfigureAwait(false);

                int streamId = await connection.ReadRequestHeaderAsync().ConfigureAwait(false);
                await connection.WriteFrameAsync(new AltSvcFrame($"https://{firstServer.Address.IdnHost}:{firstServer.Address.Port}", $"h3=\"{secondServer.Address.IdnHost}:{secondServer.Address.Port}\"", streamId: 0)).ConfigureAwait(false);
                await connection.SendDefaultResponseAsync(streamId).ConfigureAwait(false);
            });

            await new[] { firstResponseTask, serverTask }.WhenAllOrAnyFailed(60_000).ConfigureAwait(false); // Allow to fail due to hang and QuicException

            HttpResponseMessage firstResponse = firstResponseTask.Result;
            Assert.True(firstResponse.IsSuccessStatusCode);

            await AltSvc_Upgrade_Success(firstServer, secondServer, client).ConfigureAwait(false);
            listener?.Dispose();
        }

        [Fact]
        public async Task AltSvc_ResponseFrame_UpgradeFrom20_Success()
        {
            using Http2LoopbackServer firstServer = Http2LoopbackServer.CreateServer();
            using Http3LoopbackServer secondServer = CreateHttp3LoopbackServer();
            using HttpClient client = CreateHttpClient(HttpVersion.Version20);

            Task<HttpResponseMessage> firstResponseTask = client.GetAsync(firstServer.Address);
            Task serverTask = Task.Run(async () =>
            {
                await using Http2LoopbackConnection connection = await firstServer.EstablishConnectionAsync().ConfigureAwait(false);

                int streamId = await connection.ReadRequestHeaderAsync().ConfigureAwait(false);
                await connection.SendDefaultResponseHeadersAsync(streamId).ConfigureAwait(false);
                await connection.WriteFrameAsync(new AltSvcFrame("", $"h3=\"{secondServer.Address.IdnHost}:{secondServer.Address.Port}\"", streamId)).ConfigureAwait(false);
                await connection.SendResponseDataAsync(streamId, Array.Empty<byte>(), true).ConfigureAwait(false);
            });

            await new[] { firstResponseTask, serverTask }.WhenAllOrAnyFailed(60_000).ConfigureAwait(false);

            HttpResponseMessage firstResponse = firstResponseTask.Result;
            Assert.True(firstResponse.IsSuccessStatusCode);

            await AltSvc_Upgrade_Success(firstServer, secondServer, client).ConfigureAwait(false);
        }

        private async Task AltSvc_Upgrade_Success(GenericLoopbackServer firstServer, Http3LoopbackServer secondServer, HttpClient client)
        {
            Task<HttpResponseMessage> secondResponseTask = client.GetAsync(firstServer.Address);
            Task<HttpRequestData> secondRequestTask = secondServer.AcceptConnectionSendResponseAndCloseAsync();

            await new[] { (Task)secondResponseTask, secondRequestTask }.WhenAllOrAnyFailed(60_000).ConfigureAwait(false);

            HttpRequestData secondRequest = secondRequestTask.Result;
            using HttpResponseMessage secondResponse = secondResponseTask.Result;

            string altUsed = secondRequest.GetSingleHeaderValue("Alt-Used");
            Assert.Equal($"{secondServer.Address.IdnHost}:{secondServer.Address.Port}", altUsed);
            Assert.True(secondResponse.IsSuccessStatusCode);
        }
    }
}

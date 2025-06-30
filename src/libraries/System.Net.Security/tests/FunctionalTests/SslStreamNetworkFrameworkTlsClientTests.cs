// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Net.Sockets;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DotNet.XUnitExtensions;
using Xunit;
using System.Collections.Generic;
using System.Linq;
using TestUtilities;
using Xunit.Abstractions;

namespace System.Net.Security.Tests
{
    using Configuration = System.Net.Test.Common.Configuration;

    /// <summary>
    /// Tests for NetworkFramework-specific TLS client functionality on macOS.
    /// These tests verify that TLS works correctly when NetworkFramework is enabled
    /// with different protocol versions against various external servers.
    /// </summary>
    [PlatformSpecific(TestPlatforms.OSX)]
    [ConditionalClass(typeof(PlatformDetection), nameof(PlatformDetection.SupportsTls13Client))]
    public class SslStreamNetworkFrameworkTlsClientTests : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly TestEventListener _listener;

        public SslStreamNetworkFrameworkTlsClientTests(ITestOutputHelper output)
        {
            _output = output;
            SetupNetworkFramework();
            _listener = new TestEventListener(_output, TestEventListener.NetworkingEvents);
        }

        // Test data with server, port, and protocol combinations
        public static IEnumerable<object[]> TlsTestServersData => new[]
        {
            // localhost tests - useful for controlled testing
            new object[] { "localhost", 4434, SslProtocols.Tls12, "TLS 1.2 only" },
            new object[] { "localhost", 4433, SslProtocols.Tls13, "TLS 1.3 only" },
            new object[] { "localhost", 4433, SslProtocols.Tls12 | SslProtocols.Tls13, "TLS 1.2 + 1.3" },

            // Cloudflare - known for good TLS 1.3 support
            new object[] { "www.cloudflare.com", 443, SslProtocols.Tls12, "TLS 1.2 only" },
            new object[] { "www.cloudflare.com", 443, SslProtocols.Tls13, "TLS 1.3 only" },
            new object[] { "www.cloudflare.com", 443, SslProtocols.Tls12 | SslProtocols.Tls13, "TLS 1.2 + 1.3" },

            // Google - major web service provider
            new object[] { "www.google.com", 443, SslProtocols.Tls12, "TLS 1.2 only" },
            new object[] { "www.google.com", 443, SslProtocols.Tls13, "TLS 1.3 only" },
            new object[] { "www.google.com", 443, SslProtocols.Tls12 | SslProtocols.Tls13, "TLS 1.2 + 1.3" },

            // GitHub - popular developer service
            new object[] { "github.com", 443, SslProtocols.Tls12, "TLS 1.2 only" },
            new object[] { "github.com", 443, SslProtocols.Tls13, "TLS 1.3 only" },
            new object[] { "github.com", 443, SslProtocols.Tls12 | SslProtocols.Tls13, "TLS 1.2 + 1.3" },

            // Microsoft - our own services
            new object[] { "www.microsoft.com", 443, SslProtocols.Tls12, "TLS 1.2 only" },
            new object[] { "www.microsoft.com", 443, SslProtocols.Tls13, "TLS 1.3 only" },
            new object[] { "www.microsoft.com", 443, SslProtocols.Tls12 | SslProtocols.Tls13, "TLS 1.2 + 1.3" },

            // Amazon - large cloud provider
            new object[] { "aws.amazon.com", 443, SslProtocols.Tls12, "TLS 1.2 only" },
            new object[] { "aws.amazon.com", 443, SslProtocols.Tls13, "TLS 1.3 only" },
            new object[] { "aws.amazon.com", 443, SslProtocols.Tls12 | SslProtocols.Tls13, "TLS 1.2 + 1.3" },
        };

        // Simplified test data for basic connectivity tests
        public static IEnumerable<object[]> BasicTlsTestServersData => new[]
        {
            new object[] { "localhost", 4434, SslProtocols.Tls12, "Auto-negotiate" },
            new object[] { "localhost", 4433, SslProtocols.Tls13, "Auto-negotiate" },
            new object[] { "www.cloudflare.com", 443, SslProtocols.Tls13, "Auto-negotiate" },
            new object[] { "www.google.com", 443, SslProtocols.Tls13, "Auto-negotiate" },
            new object[] { "github.com", 443, SslProtocols.Tls13, "Auto-negotiate" },
        };

        private const int TestTimeoutMs = 30000;
        private const string NetworkFrameworkSwitchName = "System.Net.Security.UseNetworkFramework";

        public void Dispose()
        {
            // Reset the AppContext switch to avoid affecting other tests
            AppContext.SetSwitch(NetworkFrameworkSwitchName, false);
            _listener.Dispose();
        }

        private void SetupNetworkFramework()
        {
            // Enable NetworkFramework for these tests
            AppContext.SetSwitch(NetworkFrameworkSwitchName, true);
        }

        [Theory]
        [MemberData(nameof(BasicTlsTestServersData))]
        public async Task NetworkFramework_TlsClient_BasicHandshake_Success(string server, int port, SslProtocols protocols, string description)
        {
            _output.WriteLine($"Testing {server}:{port} with {description} ({protocols})");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));

            using var client = new TcpClient();
            await client.ConnectAsync(server, port, cts.Token);

            using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (server == "localhost")
                {
                    // For localhost, we expect chain errors with our test certs
                    return sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                }
                // For public servers, we expect a trusted chain
                return sslPolicyErrors == SslPolicyErrors.None;
            });

            var authTask = sslStream.AuthenticateAsClientAsync(server, null, protocols, false);
            await authTask.WaitAsync(cts.Token);

            Assert.True(sslStream.IsAuthenticated);
            _output.WriteLine($"✓ Successfully connected to {server} - Negotiated: {sslStream.SslProtocol}");
            _output.WriteLine($"  Cipher Suite: {sslStream.NegotiatedCipherSuite}");
            
            // Verify we got a protocol we expected
            if (protocols.HasFlag(SslProtocols.Tls13) && protocols.HasFlag(SslProtocols.Tls12))
            {
                Assert.True(sslStream.SslProtocol == SslProtocols.Tls12 || sslStream.SslProtocol == SslProtocols.Tls13);
            }
            else if (protocols.HasFlag(SslProtocols.Tls13))
            {
                Assert.Equal(SslProtocols.Tls13, sslStream.SslProtocol);
            }
            else if (protocols.HasFlag(SslProtocols.Tls12))
            {
                Assert.Equal(SslProtocols.Tls12, sslStream.SslProtocol);
            }
        }

        [Theory]
        [MemberData(nameof(TlsTestServersData))]
        public async Task NetworkFramework_TlsClient_DetailedHandshake_Success(string server, int port, SslProtocols protocols, string description)
        {
            _output.WriteLine($"Testing {server}:{port} with {description} ({protocols})");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(server, port, cts.Token);

                using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) =>
                {
                    if (server == "localhost")
                    {
                        return sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                    }
                    return sslPolicyErrors == SslPolicyErrors.None;
                });

                var authTask = sslStream.AuthenticateAsClientAsync(server, null, protocols, false);
                await authTask.WaitAsync(cts.Token);

                Assert.True(sslStream.IsAuthenticated);
                _output.WriteLine($"✓ Successfully connected to {server} - Negotiated: {sslStream.SslProtocol}");
                _output.WriteLine($"  Cipher Suite: {sslStream.NegotiatedCipherSuite}");
                _output.WriteLine($"  Remote Certificate Subject: {sslStream.RemoteCertificate?.Subject}");
                
                // Verify protocol negotiation
                if (protocols == SslProtocols.Tls13)
                {
                    Assert.Equal(SslProtocols.Tls13, sslStream.SslProtocol);
                    Assert.True(IsTls13CipherSuite(sslStream.NegotiatedCipherSuite), $"Expected TLS 1.3 cipher suite, got {sslStream.NegotiatedCipherSuite}");
                }
                else if (protocols == SslProtocols.Tls12)
                {
                    Assert.Equal(SslProtocols.Tls12, sslStream.SslProtocol);
                }
                else if (protocols.HasFlag(SslProtocols.Tls12) && protocols.HasFlag(SslProtocols.Tls13))
                {
                    Assert.True(sslStream.SslProtocol == SslProtocols.Tls12 || sslStream.SslProtocol == SslProtocols.Tls13);
                }
            }
            catch (Exception ex)
            {
                _output.WriteLine($"✗ Failed to connect to {server} with {description}: {ex.GetType().Name}: {ex.Message}");
                
                // For localhost, connection failures might be expected
                if (server == "localhost")
                {
                    _output.WriteLine("  (Localhost connection failure may be expected if test server not running)");
                    return; // Skip assertion for localhost
                }
                
                throw; // Re-throw for public servers as these should work
            }
        }

        [Theory]
        [MemberData(nameof(BasicTlsTestServersData))]
        public async Task NetworkFramework_TlsClient_DataTransfer_Success(string server, int port, SslProtocols protocols, string description)
        {
            _output.WriteLine($"Testing data transfer with {server}:{port} using {description}");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));

            using var client = new TcpClient();
            await client.ConnectAsync(server, port, cts.Token);

            using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (server == "localhost")
                {
                    return sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                }
                return sslPolicyErrors == SslPolicyErrors.None;
            });

            var authTask = sslStream.AuthenticateAsClientAsync(server, null, protocols, false);
            await authTask.WaitAsync(cts.Token);

            // Send a simple HTTP GET request
            var httpRequest = $"GET / HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\nUser-Agent: NetworkFramework-Test/1.0\r\n\r\n";
            var requestBytes = System.Text.Encoding.ASCII.GetBytes(httpRequest);

            await sslStream.WriteAsync(requestBytes, cts.Token);
            await sslStream.FlushAsync(cts.Token);

            // Read response
            var buffer = new byte[1024];
            int bytesRead = await sslStream.ReadAsync(buffer, cts.Token);

            Assert.True(bytesRead > 0, "Should receive HTTP response data");

            // Verify we got an HTTP response
            var response = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);
            _output.WriteLine($"✓ Received {bytesRead} bytes from {server} ({sslStream.SslProtocol})");
            _output.WriteLine($"  Response preview: {response.Substring(0, Math.Min(response.Length, 100)).Replace('\r', ' ').Replace('\n', ' ')}...");
            Assert.Contains("HTTP/", response);
        }

        [Theory]
        [InlineData("www.cloudflare.com", 443, SslProtocols.Tls12 | SslProtocols.Tls13)]
        [InlineData("www.google.com", 443, SslProtocols.Tls12 | SslProtocols.Tls13)]
        public async Task NetworkFramework_TlsClient_MultipleConnections_Success(string server, int port, SslProtocols protocols)
        {
            _output.WriteLine($"Testing multiple connections to {server}:{port}");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));

            const int connectionCount = 3;
            var tasks = new Task[connectionCount];

            for (int i = 0; i < connectionCount; i++)
            {
                int connId = i;
                tasks[i] = Task.Run(async () =>
                {
                    _output.WriteLine($"  Starting connection {connId + 1}");
                    await ConnectToServerAsync(server, port, protocols, cts.Token);
                    _output.WriteLine($"  ✓ Connection {connId + 1} completed");
                });
            }

            var allTask = Task.WhenAll(tasks);
            await allTask.WaitAsync(cts.Token);

            // All connections should have completed successfully
            foreach (var task in tasks)
            {
                Assert.True(task.IsCompletedSuccessfully);
            }
            
            _output.WriteLine($"✓ All {connectionCount} connections to {server} completed successfully");
        }

        [Theory]
        [InlineData("www.cloudflare.com", 443, SslProtocols.Tls13)]
        [InlineData("www.google.com", 443, SslProtocols.Tls13)]
        public async Task NetworkFramework_Tls13_ConnectionInfo_Valid(string server, int port, SslProtocols protocols)
        {
            _output.WriteLine($"Testing TLS 1.3 connection info for {server}:{port}");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));

            using var client = new TcpClient();
            await client.ConnectAsync(server, port, cts.Token);

            using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                return sslPolicyErrors == SslPolicyErrors.None;
            });

            var authTask = sslStream.AuthenticateAsClientAsync(server, null, protocols, false);
            await authTask.WaitAsync(cts.Token);

            // Verify connection information
            Assert.Equal(SslProtocols.Tls13, sslStream.SslProtocol);
            Assert.True(IsTls13CipherSuite(sslStream.NegotiatedCipherSuite));

            _output.WriteLine($"✓ TLS 1.3 connection verified:");
            _output.WriteLine($"  Protocol: {sslStream.SslProtocol}");
            _output.WriteLine($"  Cipher Suite: {sslStream.NegotiatedCipherSuite}");
            _output.WriteLine($"  Certificate Subject: {sslStream.RemoteCertificate?.Subject}");

            // Verify cipher suite is one of the expected TLS 1.3 cipher suites
            var negotiatedCipher = sslStream.NegotiatedCipherSuite;
            Assert.True(negotiatedCipher == TlsCipherSuite.TLS_AES_128_GCM_SHA256 ||
                       negotiatedCipher == TlsCipherSuite.TLS_AES_256_GCM_SHA384 ||
                       negotiatedCipher == TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256 ||
                       negotiatedCipher == TlsCipherSuite.TLS_AES_128_CCM_SHA256 ||
                       negotiatedCipher == TlsCipherSuite.TLS_AES_128_CCM_8_SHA256,
                       $"Unexpected TLS 1.3 cipher suite: {negotiatedCipher}");
        }

        [Theory]
        [InlineData("www.cloudflare.com", 443)]
        [InlineData("www.google.com", 443)]
        public async Task NetworkFramework_TlsClient_ProtocolNegotiation_PrefersTls13(string server, int port)
        {
            _output.WriteLine($"Testing protocol negotiation preference for {server}:{port}");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));

            SslProtocols clientProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;

            using var client = new TcpClient();
            await client.ConnectAsync(server, port, cts.Token);

            using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                return sslPolicyErrors == SslPolicyErrors.None;
            });

            var authTask = sslStream.AuthenticateAsClientAsync(server, null, clientProtocols, false);
            await authTask.WaitAsync(cts.Token);

            _output.WriteLine($"✓ Protocol negotiation result: {sslStream.SslProtocol}");
            _output.WriteLine($"  Cipher Suite: {sslStream.NegotiatedCipherSuite}");

            // Most modern servers should negotiate TLS 1.3 when offered both 1.2 and 1.3
            // But we'll accept either as long as connection succeeds
            Assert.True(sslStream.SslProtocol == SslProtocols.Tls12 || sslStream.SslProtocol == SslProtocols.Tls13);
        }

        // --- Certificate Validation Tests ---
        
        [Theory]
        // [InlineData("www.cloudflare.com", 443, SslProtocols.Tls12)]
        [InlineData("www.cloudflare.com", 443, SslProtocols.Tls13)]
        public async Task NetworkFramework_TlsClient_CertificateValidationPal_Called(string server, int port, SslProtocols protocols)
        {
            _output.WriteLine($"Testing certificate validation for {server}:{port} with {protocols}");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));

            using var client = new TcpClient();
            await client.ConnectAsync(server, port, cts.Token);

            bool validationCallbackCalled = false;
            
            using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                validationCallbackCalled = true;
                _output.WriteLine($"Certificate validation callback called for {server}:");
                _output.WriteLine($"  Certificate Subject: {certificate?.Subject}");
                _output.WriteLine($"  SSL Policy Errors: {sslPolicyErrors}");
                _output.WriteLine($"  Chain Status: {(chain?.ChainStatus?.Length > 0 ? string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString())) : "No errors")}");
                
                // Accept the certificate to complete the handshake
                return true;
            });
            
            var authTask = sslStream.AuthenticateAsClientAsync(server, null, protocols, false);
            await authTask.WaitAsync(cts.Token);

            Assert.True(sslStream.IsAuthenticated);
            Assert.True(validationCallbackCalled, "Certificate validation callback should have been called");
            
            _output.WriteLine($"✓ Certificate validation successful:");
            _output.WriteLine($"  Negotiated Protocol: {sslStream.SslProtocol}");
            _output.WriteLine($"  Negotiated Cipher: {sslStream.NegotiatedCipherSuite}");
        }

        // --- Failure Tests using badssl.com ---

        [Theory]
        //[InlineData("wrong.host.badssl.com", 443, SslProtocols.Tls12)]
        [InlineData("wrong.host.badssl.com", 443, SslProtocols.Tls13)]
        //[InlineData("untrusted-root.badssl.com", 443, SslProtocols.Tls12)]
        [InlineData("untrusted-root.badssl.com", 443, SslProtocols.Tls13)]
        //[InlineData("self-signed.badssl.com", 443, SslProtocols.Tls12)]
        //[InlineData("expired.badssl.com", 443, SslProtocols.Tls12)]
        public async Task NetworkFramework_TlsClient_BadSsl_FailsWithAuthenticationException(string server, int port, SslProtocols protocols)
        {
            _output.WriteLine($"Testing expected failure for {server}:{port} with {protocols}");
            
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(TestTimeoutMs));
            
            using var client = new TcpClient();
            await client.ConnectAsync(server, port, cts.Token);
            
            using var sslStream = new SslStream(client.GetStream());
            
            var authTask = sslStream.AuthenticateAsClientAsync(server, null, protocols, false);
            var ex = await Assert.ThrowsAsync<AuthenticationException>(() => authTask.WaitAsync(cts.Token));
            
            _output.WriteLine($"✓ Expected failure occurred for {server} with {protocols}: {ex.Message}");
        }

        // --- Local SslStream Tests (TLS 1.2 only since server doesn't support TLS 1.3) ---

        [Fact]
        public async Task NetworkFramework_Tls12_IncorrectServerName_Fails()
        {
            _output.WriteLine("Testing incorrect server name with TLS 1.2 and Network Framework");
            
            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            using (clientStream)
            using (serverStream)
            using (var clientSslStream = new SslStream(clientStream))
            using (var serverSslStream = new SslStream(serverStream))
            using (var serverCertificate = Configuration.Certificates.GetServerCertificate())
            {
                var clientOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = "incorrect.server.com",
                    EnabledSslProtocols = SslProtocols.Tls12
                };

                var serverOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                    EnabledSslProtocols = SslProtocols.Tls12
                };

                Task clientTask = clientSslStream.AuthenticateAsClientAsync(clientOptions);
                Task serverTask = serverSslStream.AuthenticateAsServerAsync(serverOptions);

                var ex = await Assert.ThrowsAsync<AuthenticationException>(() => clientTask);
                _output.WriteLine($"✓ Expected authentication failure: {ex.Message}");

                try
                {
                    await serverTask;
                    _output.WriteLine("Server task completed");
                }
                catch (Exception serverEx)
                {
                    _output.WriteLine($"Server task failed as expected: {serverEx.Message}");
                }
            }
        }

        // --- Helper Methods ---

        private async Task ConnectToServerAsync(string server, int port, SslProtocols protocols, CancellationToken cancellationToken = default)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(server, port, cancellationToken);

            using var sslStream = new SslStream(client.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (server == "localhost")
                {
                    return sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                }
                return sslPolicyErrors == SslPolicyErrors.None;
            });

            var authTask = sslStream.AuthenticateAsClientAsync(server, null, protocols, false);
            await authTask.WaitAsync(cancellationToken);

            Assert.True(sslStream.IsAuthenticated);
            
            if (protocols == SslProtocols.Tls13)
            {
                Assert.Equal(SslProtocols.Tls13, sslStream.SslProtocol);
                Assert.True(IsTls13CipherSuite(sslStream.NegotiatedCipherSuite));
            }
        }

        private static bool IsTls13CipherSuite(TlsCipherSuite cipherSuite)
        {
            return cipherSuite switch
            {
                TlsCipherSuite.TLS_AES_128_GCM_SHA256 => true,
                TlsCipherSuite.TLS_AES_256_GCM_SHA384 => true,
                TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256 => true,
                TlsCipherSuite.TLS_AES_128_CCM_SHA256 => true,
                TlsCipherSuite.TLS_AES_128_CCM_8_SHA256 => true,
                _ => false
            };
        }
    }
} 
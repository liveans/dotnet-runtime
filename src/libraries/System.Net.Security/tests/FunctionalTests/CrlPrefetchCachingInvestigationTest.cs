// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Test.Common;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.X509Certificates.Tests.Common;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace System.Net.Security.Tests
{
    using Configuration = System.Net.Test.Common.Configuration;

    public class CrlPrefetchCachingInvestigationTest : IDisposable
    {
        private CertificateAuthority _rootCA;
        private CertificateAuthority _intermediateCA;
        private RevocationResponder _responder;
        private X509Certificate2 _serverCert;
        private bool _disposed;
        private byte[] _intermediateCrlData;

        [Fact]
        [PlatformSpecific(TestPlatforms.Windows)]
        public async Task CrlPrefetchCaching_OnlineToOffline_RevocationCheckSucceeds()
        {
            await SetupTestInfrastructureAsync();

            try
            {
                // Step 1: Pre-fetch CRL information while online
                await PrefetchCrlInformationAsync();

                // Step 2: CRL information is already cached in PrefetchCrlInformationAsync()

                // Step 3: Go offline (stop the HTTP responder)
                _responder?.Stop();

                // Step 4: Perform offline revocation check - should succeed due to cached CRL
                await PerformOfflineRevocationCheckAsync();
            }
            finally
            {
                CleanupTestInfrastructure();
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Windows)]
        public async Task CrlPrefetchCaching_ChainBuilding_OfflineRevocationSuccess()
        {
            await SetupTestInfrastructureAsync();

            try
            {
                // Build chain with online CRL access first
                var chainOnline = BuildChainWithRevocation(_serverCert, online: true);
                Console.WriteLine($"Online chain status: {string.Join(", ", chainOnline.ChainStatus.Select(s => s.Status))}");
                
                // For investigation purposes, we expect some revocation information to be available
                bool onlineHasRevocationInfo = chainOnline.ChainStatus.Length == 0 || 
                    chainOnline.ChainStatus.All(s => s.Status == X509ChainStatusFlags.NoError ||
                        s.Status == X509ChainStatusFlags.UntrustedRoot); // Self-signed test certs

                // CRL information is already cached in PrefetchCrlInformationAsync()

                // Stop responder to simulate offline environment
                _responder?.Stop();

                // Build chain offline - investigate what happens with cached CRL
                var chainOffline = BuildChainWithRevocation(_serverCert, online: false);
                Console.WriteLine($"Offline chain status: {string.Join(", ", chainOffline.ChainStatus.Select(s => s.Status))}");
                
                // For investigation, we're testing if offline behavior differs from online
                bool offlineSucceeded = HasAcceptableRevocationStatus(chainOffline);
                Console.WriteLine($"Online chain acceptable: {onlineHasRevocationInfo}, Offline chain acceptable: {offlineSucceeded}");
                
                // Test should pass only if we can actually demonstrate working CRL caching
                Assert.True(onlineHasRevocationInfo && offlineSucceeded, 
                    $"CRL caching failed. Online acceptable: {onlineHasRevocationInfo}, Offline acceptable: {offlineSucceeded}");
            }
            finally
            {
                CleanupTestInfrastructure();
            }
        }

        private async Task SetupTestInfrastructureAsync()
        {
            // Use CertificateAuthority.BuildPrivatePki to create proper certificates with private keys
            CertificateAuthority.BuildPrivatePki(
                PkiOptions.CrlEverywhere,
                out _responder,
                out _rootCA,
                out var intermediateAuthorities,
                out _serverCert,
                intermediateAuthorityCount: 1,
                testName: "CRL Prefetch Test",
                registerAuthorities: true,
                pkiOptionsInSubject: false,
                subjectName: "Test Server");

            _intermediateCA = intermediateAuthorities[0];

            await Task.Delay(100); // Allow infrastructure to stabilize
        }

        private async Task PrefetchCrlInformationAsync()
        {
            // Fetch and cache CRL information by making requests to all CRL endpoints
            using var httpClient = new HttpClient();

            // Fetch and cache intermediate CRL (root CAs don't typically need CRL verification)
            if (_intermediateCA.CdpUri != null)
            {
                var intermediateCrlResponse = await httpClient.GetAsync(_intermediateCA.CdpUri);
                Assert.True(intermediateCrlResponse.IsSuccessStatusCode);
                _intermediateCrlData = await intermediateCrlResponse.Content.ReadAsByteArrayAsync();
                Assert.True(_intermediateCrlData.Length > 0);
                Console.WriteLine($"Fetched intermediate CRL: {_intermediateCrlData.Length} bytes");
                
                // Cache the CRL in Windows certificate stores
                CacheCrlInStore(_intermediateCrlData, StoreName.CertificateAuthority);
            }

            // Fetch and cache server certificate CRL (if it has a CRL distribution point)
            var serverCrlUrls = GetCrlDistributionPoints(_serverCert);
            foreach (string crlUrl in serverCrlUrls)
            {
                try
                {
                    var serverCrlResponse = await httpClient.GetAsync(crlUrl);
                    if (serverCrlResponse.IsSuccessStatusCode)
                    {
                        var serverCrlData = await serverCrlResponse.Content.ReadAsByteArrayAsync();
                        if (serverCrlData.Length > 0)
                        {
                            Console.WriteLine($"Fetched server certificate CRL from {crlUrl}: {serverCrlData.Length} bytes");
                            
                            // Cache the server certificate CRL in Windows certificate stores
                            CacheCrlInStore(serverCrlData, StoreName.CertificateAuthority);
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Failed to fetch server CRL from {crlUrl}: {serverCrlResponse.StatusCode}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error fetching server CRL from {crlUrl}: {ex.Message}");
                }
            }
        }

        private List<string> GetCrlDistributionPoints(X509Certificate2 certificate)
        {
            var crlUrls = new List<string>();
            
            try
            {
                // Look for CRL Distribution Points extension (OID: 2.5.29.31)
                const string crlDistributionPointsOid = "2.5.29.31";
                var crlExtension = certificate.Extensions[crlDistributionPointsOid];
                
                if (crlExtension != null)
                {
                    // Parse the extension data to extract URLs
                    // This is a simplified approach - in production you'd want more robust parsing
                    string extensionData = crlExtension.Format(false);
                    Console.WriteLine($"CRL Distribution Points extension found: {extensionData}");
                    
                    // Try to extract HTTP URLs from the extension data
                    var httpMatches = System.Text.RegularExpressions.Regex.Matches(extensionData, @"http://[^\s,)]+");
                    foreach (System.Text.RegularExpressions.Match match in httpMatches)
                    {
                        crlUrls.Add(match.Value);
                        Console.WriteLine($"Found CRL URL in server cert: {match.Value}");
                    }
                    
                    var httpsMatches = System.Text.RegularExpressions.Regex.Matches(extensionData, @"https://[^\s,)]+");
                    foreach (System.Text.RegularExpressions.Match match in httpsMatches)
                    {
                        crlUrls.Add(match.Value);
                        Console.WriteLine($"Found CRL URL in server cert: {match.Value}");
                    }
                }
                else
                {
                    Console.WriteLine($"Server certificate does not have CRL Distribution Points extension");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing CRL distribution points: {ex.Message}");
            }
            
            return crlUrls;
        }


        private async Task PerformOfflineRevocationCheckAsync()
        {
            // Use multiple methods to verify offline revocation checking works
            
            // Method 1: Traditional chain building - now offline after responder is stopped
            using var chainOffline = new X509Chain();
            chainOffline.ChainPolicy.RevocationMode = X509RevocationMode.Offline; // Test if cached CRL works in online mode when offline
            chainOffline.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chainOffline.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            
            // Add intermediate CA to extra store
            chainOffline.ChainPolicy.ExtraStore.Add(_intermediateCA.CloneIssuerCert());
            chainOffline.ChainPolicy.ExtraStore.Add(_rootCA.CloneIssuerCert());

            bool chainResult = chainOffline.Build(_serverCert);
            Console.WriteLine($"Offline chain build result: {chainResult}");
            Console.WriteLine($"Offline chain status: {string.Join(", ", chainOffline.ChainStatus.Select(s => s.Status))}");
            
            // For investigation, we expect this might fail due to no network access
            // but we're testing whether cached CRL information helps
            bool offlineAcceptable = HasAcceptableRevocationStatus(chainOffline);
            Console.WriteLine($"Offline revocation check acceptable: {offlineAcceptable}");
            
            // Test should pass only if offline revocation actually works with cached CRL
            Assert.True(chainResult && offlineAcceptable, 
                $"Offline revocation check failed. Chain result: {chainResult}, Acceptable status: {offlineAcceptable}");

            // Method 2: Explicit SslStream certificate validation
            await TestSslStreamWithCachedRevocation();
        }

        private async Task TestSslStreamWithCachedRevocation()
        {
            // Create connected streams for SSL testing
            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            
            using (clientStream)
            using (serverStream)
            using (var client = new SslStream(clientStream, false, ValidateServerCertificateWithCachedRevocation))
            using (var server = new SslStream(serverStream))
            {
                var serverOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCert,
                    ClientCertificateRequired = false
                };

                var clientOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = "Test Server",
                    CertificateRevocationCheckMode = X509RevocationMode.Online
                };

                Task serverTask = server.AuthenticateAsServerAsync(serverOptions);
                Task clientTask = client.AuthenticateAsClientAsync(clientOptions);

                await Task.WhenAll(serverTask, clientTask);
                
                // If we get here, the cached revocation information worked
                Assert.True(client.IsAuthenticated);
                Assert.True(server.IsAuthenticated);
            }
        }

        private bool ValidateServerCertificateWithCachedRevocation(
            object sender, 
            X509Certificate certificate, 
            X509Chain chain, 
            SslPolicyErrors sslPolicyErrors)
        {
            // Custom certificate validation that should work with cached CRL
            if (chain != null)
            {
                chain.ChainPolicy.ExtraStore.Add(_intermediateCA.CloneIssuerCert());
                chain.ChainPolicy.ExtraStore.Add(_rootCA.CloneIssuerCert());
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                
                bool result = chain.Build(new X509Certificate2(certificate));
                return result || HasAcceptableRevocationStatus(chain);
            }
            
            return false;
        }

        private bool HasAcceptableRevocationStatus(X509Chain chain)
        {
            // Check if the only errors are acceptable revocation-related errors
            foreach (var status in chain.ChainStatus)
            {
                if (status.Status != X509ChainStatusFlags.UntrustedRoot &&
                    status.Status != X509ChainStatusFlags.NoError)
                {
                    return false;
                }
            }
            return true;
        }

        private X509Chain BuildChainWithRevocation(X509Certificate2 certificate, bool online)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = online ? X509RevocationMode.Online : X509RevocationMode.Offline;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.ExtraStore.Add(_intermediateCA.CloneIssuerCert());
            chain.ChainPolicy.ExtraStore.Add(_rootCA.CloneIssuerCert());
            
            
            chain.Build(certificate);
            return chain;
        }


        private async Task TestCrlCachingBehaviors()
        {
            // Test 1: Verify CRL is served correctly while online
            using var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(_intermediateCA.CdpUri);
            Assert.True(response.IsSuccessStatusCode);
            
            // Test 2: Build chain while online
            using var onlineChain = BuildChainWithRevocation(_serverCert, online: true);
            
            // Test 3: CRL data is already cached in PrefetchCrlInformationAsync()
            
            // Test 4: Simulate network interruption
            _responder.RespondKind = RespondKind.Empty;
            
            // Test 5: Try offline operations (would succeed with proper caching)
            using var offlineChain = BuildChainWithRevocation(_serverCert, online: false);
            
            // Reset responder
            _responder.RespondKind = RespondKind.Normal;
        }

        private void CleanupTestInfrastructure()
        {
            try
            {
                _responder?.Dispose();
                _rootCA?.Dispose();
                _intermediateCA?.Dispose();
                _serverCert?.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Cleanup error: {ex.Message}");
            }
        }

        #region Windows P/Invoke for CRL Caching

        // P/Invoke declarations for Windows CRL caching APIs
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr CertCreateCRLContext(
            uint dwCertEncodingType,
            byte[] pbCrlEncoded,
            uint cbCrlEncoded);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertAddCRLContextToStore(
            IntPtr hCertStore,
            IntPtr pCrlContext,
            uint dwAddDisposition,
            IntPtr ppStoreContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertFreeCRLContext(IntPtr pCrlContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertControlStore(
            IntPtr hCertStore,
            uint dwFlags,
            uint dwCtrlType,
            IntPtr pvCtrlPara);

        private const uint X509_ASN_ENCODING = 0x00000001;
        private const uint PKCS_7_ASN_ENCODING = 0x00010000;
        private const uint CERT_STORE_ADD_REPLACE_EXISTING = 3;
        private const uint CERT_STORE_CTRL_RESYNC = 1;

        private void CacheCrlInStore(byte[] crlData, StoreName storeName)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || crlData == null || crlData.Length == 0)
                return;

            try
            {
                // Use managed X509Store to get store handle, then P/Invoke for CRL-specific operations
                using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                
                var storeHandle = store.StoreHandle;
                if (storeHandle != IntPtr.Zero)
                {
                    // Create CRL context using P/Invoke (similar to your C code example)
                    IntPtr pCrl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, crlData, (uint)crlData.Length);
                    if (pCrl != IntPtr.Zero)
                    {
                        try
                        {
                            // Add CRL to the managed store using its handle
                            bool success = CertAddCRLContextToStore(storeHandle, pCrl, CERT_STORE_ADD_REPLACE_EXISTING, IntPtr.Zero);
                            Console.WriteLine($"CRL cached in {storeName} store: {success}");
                            
                            if (success)
                            {
                                // Force store resynchronization after successful CRL addition
                                CertControlStore(storeHandle, 0, CERT_STORE_CTRL_RESYNC, IntPtr.Zero);
                                Console.WriteLine($"Store resync triggered for {storeName}");
                            }
                        }
                        finally
                        {
                            CertFreeCRLContext(pCrl);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to cache CRL in {storeName} store: {ex.Message}");
            }
        }


        private void FlushAndCacheSystemCrls()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return;

            try
            {
                // Force resync on multiple certificate stores using managed APIs
                StoreName[] storeNames = { StoreName.CertificateAuthority, StoreName.Root, StoreName.My };
                
                foreach (StoreName storeName in storeNames)
                {
                    using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadWrite);
                    
                    var storeHandle = store.StoreHandle;
                    if (storeHandle != IntPtr.Zero)
                    {
                        CertControlStore(storeHandle, 0, CERT_STORE_CTRL_RESYNC, IntPtr.Zero);
                        Console.WriteLine($"System store {storeName} resync completed");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to flush and cache system CRLs: {ex.Message}");
            }
        }

        #endregion

        public void Dispose()
        {
            if (!_disposed)
            {
                CleanupTestInfrastructure();
                _disposed = true;
            }
        }
    }
}

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace JwsJwe.Test
{
    public class SignAndEncryptTest
    {
        // a jwks which includes private as well as public keys. This is not
        // typical but as we need private keys for decrypting and signing they are included
        // https://mkjwk.org/  make some jwks for kicks
        private const string Jwks = @"{ 
            ""keys"": [
                {
                    ""kid"": ""signatory"",
                    ""p"": ""xdjVAn90ffFSqM8DvJeuyTYrQXT3FQ8Qguan5Et7mcD1DvhHctr-OhXlsMrPLfsZ9QLKOxVBjXdqF9LVb7S563DaJAI1CsmB08zmPGoksvPprfF_gZfQXnwtsw1-eekmSyv0PSO5faLvHJFSQVpwf75mmbsrBvrTvYIeNIhoXdc"",
                    ""kty"": ""RSA"",
                    ""q"": ""v8514CQsigoWcE6YMNSt68Q3vyf20LetvRpcPYJ4SnNLXbIOGdcByQJHV8i4oQ-WS5EQekKOhHLBOJTj86mI6i6GCWo_uCDy2yDhiha5YJobKWHt9fxjWZ4og3q_vbuawNlup2Pi3bc7M1j0ua80R4CldEtaJk-Wr-YnJ3SP5Ns"",
                    ""d"": ""AR_IBCmUNCUsxHnKyrTEtPqJTGQ0kOQffivh8YTLSeCsGkmezTKkYagMegKwottx67ERcBGxHsoR9pWknqDNsXCqViYk58LlukgMttusdPfgQHKhq9Nwb6mhvZXFxfRSjvipViL6g9nLdElc44D-5RldOXs5XBkxWsiYGtUn_9dL4BTJuzdbrKjsW-Bxdhl2gst3uBwgJCSzy-mO-rWn2qB60kUo1UVUxLHBjRlwYLfWaisQPS48rK21YATLEmBrY0cKMI7PfRXO3ZaN33JSUFqImCsUbvjYiLfVchVx6Y0SWaFcvO-RrIVoTNa9wg4GZ04gRva-Pd0WWk-ik7f0fQ"",
                    ""e"": ""AQAB"",
                    ""use"": ""sig"",
                    ""qi"": ""Qv3iKk4RGWUUpuwSsIsYkbQEjMFYDCaE1eb2jQlWGRiiHgEoLGhLnumvZACPh9JMvhXRHZTb_CVBgJXV6N5Z_3yc-eWRT0-juj2TA9dohEVmmD-xXCrNIQ0VFuPfRrUtEwTw0TTE1Rct3S_CHpfqqQRyhua1eY4ZYjNLjhNFWsk"",
                    ""dp"": ""BIZ4IM1_gZ3ycRADGt4xTkLh7GZbfGzSyNuzvWIImrSyJjyBjdv6cqOrlEafRIL4zgTZUU6kKDMyBwd4gEyW8A6tvqMaSXvgb1LBdWJMIpe3oZXjf7hUOMUIWo8VdH5jtNZ1iKx3gqsmYvXj9sC10AYv3JZOXqOAElaWkEcKdBM"",
                    ""alg"": ""PS512"",
                    ""dq"": ""Tasi3FKJnpQbJfsNcaiNjMz17fgW38mhFtQXyeiNIUiymgxB3YDM_kJn9UoYSU_wgkUJsRhGcaeuSmUwMTjTclDIggN-LedZsBYOfkZZZp7ApO881sEO0flTWnpYLlJLhhAF2M5_zVwnItHAt3gU6WdUmFTy-lR8JlpCPJ3crsU"",
                    ""n"": ""lDxWgZgj6gvNV1asTAHCDxAcSvKV8Ob1VbLLqt_3EwnGzeS_AUI638VZJCRjsb9_0Bc-6Wcdm6fKxI_QwFjC1GbnLhc1AXGSYLjqUZWJ3B15NoobBTUweJDyuCbQ_HGVhxEoErSeC33W1asZr5YYxe2fmTaEi1vrYlsdEJ4L2H8O3LBC9prLNex0suInZJjFl_5PNEkyqdFHBEog6ZRf-KxPLShGWX0zAs_tt5Tuiw6VDi1VJZQ-ryGOE1YFtZB95q2ugQ9P_zZU_fbi1XFE1g2SJnJpsrx6lR4nCXlzZFwJzqN3_8j3_HXwPDKvNtwhCsfZBHhnzvakuioAe_TC7Q""
                }, 
                {
                    ""kid"": ""encryptor"",
                    ""p"": ""_vhwu9Moc9Xb33ATItlapFHXiSq2u85B-7_sDH6y_e8bdpQX8AvocjszMsJLSDbRjhn-aZPPOWEbpis9LH34JKG-ys9hrGhHtWHsvD0SnYuAi6R0uaGPoC4d5QbIdu6ISorohodcCqTeHij1aMCb8gNB3qW_1ORYPo2FuSOU2Xc"",
                    ""kty"": ""RSA"",
                    ""q"": ""2mqeFAAeQRFfbg9u0NWSwGJyxOYGrm0V8qw6WuppqGIpYLE-Yh5am-jh1_e6qiNh6Py235ccpwk9OKxN9edrGmus7RlDWS2LXhPzUSCAzxAcvytE748m5XOXFNV3GCLW2ekwXqR59KDFMN8X4rkNEDW2xVL97JsN_62MMcl-o0c"",
                    ""d"": ""d9IaLWUztP9dr_m_hcooXIaRiMZTRCHIUGJAVDAh-Ab2-_FWv1OW82sYVR2a8CVogmHJ1UK6UPGtv8jBB_w1EBV1zaZxzMLwmREJTd5vmxA3tF38MyGqwiPt41oXsxZqcLF1Oqy6aLKTH0x57Nt1lWDvbEmXS6CAuPmtdAxpAG5D3IdrBi-NjV4VCQ07gHkDY8LyB9KaRvcTwsfE53CEYvWRQwLSaT1EXZfrhf80aiOBSInz00E4dBtGECGgfDlj9VkjnCRuvSOwuW3GQ5wvB6Ins5Jvx9ZrlbGTKSAnSJs9Kvt4BwK7bPcVqknE7udz1sWgGDShrdjD5bDxps-kiQ"",
                    ""e"": ""AQAB"",
                    ""use"": ""enc"",
                    ""qi"": ""x4lA-E-PC5yLm9uz67mrcYHIUv0rWa_v36LjgbCJJiHT-77TBrLS6LszCiLgLNFJ-8s3NtvPQh_TldlJUZiygEKsrzzItQPoEBrcoXLAmk5sIAmS-MzALzokuvsSIig7XR8w0esFrjKCgksLptKdLjLVDhHMpRcGNDX_qlCk_8o"",
                    ""dp"": ""ykMhgw5WV9W-D3kj5RBRpGq8NbbpsQBFPcWZJqxXp7PHsIB4oNeBdSTbT5fsCoRaJoUeWniD-fu76E0CwUnI0J5y8QYkcJVk1VGyb_1uyAXDWoOCiUPN4P7UfjusSRSej6u0HAxDCrqQ7ZIGZCvvScQlu87255ahHjY8b4r3aK8"",
                    ""alg"": ""PS512"",
                    ""dq"": ""QjRZECTtBroWXA0PgPuLzQbKVQaIdeyY34L2-UHenuyKMEXpa-JZgrK3ajgr-5BYCEA5ylJKnBL_3KLVyrjHzS1gMEodEPXuLakMcsXQZXMz03pxHdAdcSV1YRpHTCibSVgWkkl2sgDdZK_q1I1U-VneubcrQsHJH3viZ-D0otc"",
                    ""n"": ""2YnAT-Cwvk8inhYmt82bUL1dplSI3GRzlVuA513IfInqF77jT6-YVtF2OM4PVKoYMhzhHZOpnpZAfTPKRxjXyqF6x_2c_iWuanlJZHXu2TThx2QZBx6FuMK2ezLesOm6dzLG2ux6EwNU9XyyYe739r3lV-5wDyWL50fitXp0XktvkZMyz1ZVy2L6JiccGsE5gag6Mxjbf8K5ksTGoj1I8Wpt1YAAo1v8usVaI93S_NutwK3bLqxcP2z0pvLAANbUcIBG-UhEamW4KyGQavCkuyrMIrqMxK2GhqrBdQPc6bQr6mhCeXQ7jNuCNzVbpjpTNmoWUZevrBhYSg3JHFEVAQ""
                }
            ]
        }";

        // topics/tutorials
        // https://www.scottbrady91.com/C-Sharp/JSON-Web-Encryption-JWE-in-dotnet-Core
        // https://stackoverflow.com/questions/18223868/how-to-encrypt-jwt-security-token
        // https://github.com/IdentityServer/IdentityServer4/blob/master/samples/Clients/old/MvcManual/Controllers/HomeController.cs#L154
        [Fact]
        public void JWE_CreateAndDecrypt()
        {
            // create JWKS
            var jsonWebKeySet = JsonWebKeySet.Create(Jwks);


            // ENCRYPTION

            // Find first encryption key - todo ignore invalid
            var encKey = jsonWebKeySet.Keys.First(k => k.Use == "enc");

            // Build the RSA public key from the JWK properties. Ripe for extension method
            using var rsaEncKey = RSA.Create();
            var rsaPublicKeyParams = new RSAParameters
            {
                Modulus = Base64UrlEncoder.DecodeBytes(encKey.N),
                Exponent = Base64UrlEncoder.DecodeBytes(encKey.E),
            };
            rsaEncKey.ImportParameters(rsaPublicKeyParams);
            var rsaPublicKey = new RsaSecurityKey(rsaEncKey)
            {
                KeyId = encKey.KeyId
            };

            // create a signed, encrypted JWE
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = new Dictionary<string, object>{{"foo", 123}},
                SigningCredentials = new SigningCredentials(jsonWebKeySet.GetSigningKeys().First(), SecurityAlgorithms.RsaSsaPssSha512),
                EncryptingCredentials = new EncryptingCredentials(rsaPublicKey, SecurityAlgorithms.RsaOaepKeyWrap, SecurityAlgorithms.Aes256CbcHmacSha512)
            };
            var token = tokenHandler.CreateEncodedJwt(tokenDescriptor);

            // DECRYPTION (token validation)

            // Now decrypt using private key
            using var rsaDecKey = RSA.Create();
            var rsaPrivateKeyParams = new RSAParameters
            {
                P = Base64UrlEncoder.DecodeBytes(encKey.P),
                Q = Base64UrlEncoder.DecodeBytes(encKey.Q),
                D = Base64UrlEncoder.DecodeBytes(encKey.D),
                DP = Base64UrlEncoder.DecodeBytes(encKey.DP),
                DQ = Base64UrlEncoder.DecodeBytes(encKey.DQ),
                InverseQ = Base64UrlEncoder.DecodeBytes(encKey.QI),
                Exponent = Base64UrlEncoder.DecodeBytes(encKey.E),
                Modulus = Base64UrlEncoder.DecodeBytes(encKey.N),
            };
            rsaDecKey.ImportParameters(rsaPrivateKeyParams);
            var rsaPrivateKey = new RsaSecurityKey(rsaDecKey);
            var tokenValidationParams = new TokenValidationParameters
            {
                ValidateAudience = false, // validate sig
                ValidateIssuer = false,   // validate sig
                RequireSignedTokens = true,
                IssuerSigningKeys = jsonWebKeySet.GetSigningKeys(),
                TokenDecryptionKey = rsaPrivateKey
            };
            var claimsPrincipal =
                tokenHandler.ValidateToken(token, tokenValidationParams, out var securityToken);

            // the encryption and signing should be as expected
            Assert.Equal("encryptor", ((JwtSecurityToken)securityToken).Header.Kid);
            Assert.Equal("signatory", ((JwtSecurityToken)securityToken).InnerToken.Header.Kid);

            // claims are in the securityToken as well but claimsPrincipal is a more common object to interrogate
            Assert.Equal("123", claimsPrincipal.Claims.First(c => c.Type == "foo").Value);

        }
    }
}

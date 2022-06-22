using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OAuthMicrosoft.Models;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web;

namespace Microsoft.OAuth.Controllers
{
    public class OAuthController : Controller
    {
        private readonly HttpClient _httpClient = new HttpClient();
        private readonly IConfiguration _configuration;
        public static IConfiguration _staticConfig { get; private set; }
        private static readonly Dictionary<Guid, TokenModel> _authorizationRequests = new Dictionary<Guid, TokenModel>();

        public OAuthController(IConfiguration configuration)
        {
            _configuration = configuration;
            _staticConfig = configuration;
        }

        /// <summary>
        /// Start a new authorization request. 
        /// This creates a random state value that is used to correlate/validate the request in the callback later.
        /// </summary>
        /// <returns></returns>
        public IActionResult Authorize()
        {
            Guid state = Guid.NewGuid();

            _authorizationRequests[state] = new TokenModel() { IsPending = true };

            return new RedirectResult(GetAuthorizationUrl(state.ToString()));
        }

        /// <summary>
        /// Constructs an authorization URL with the specified state value.
        /// </summary>
        /// <param name="state"></param>
        /// <returns></returns>
        private static String GetAuthorizationUrl(String state)
        {
            UriBuilder uriBuilder = new UriBuilder(_staticConfig["ApplicationOAuth:AuthorizationUrl"]);
            var queryParams = HttpUtility.ParseQueryString(uriBuilder.Query ?? String.Empty);

            queryParams["client_id"] = _staticConfig["ApplicationOAuth:ClientID"];
            queryParams["response_type"] = "code";
            queryParams["response_mode"] = "query";
            queryParams["state"] = state;
            queryParams["scope"] = _staticConfig["ApplicationOAuth:Scopes"];
            queryParams["redirect_uri"] = _staticConfig["ApplicationOAuth:RedirectUri"];

            uriBuilder.Query = queryParams.ToString();

            return uriBuilder.ToString();
        }

        /// <summary>
        /// Callback action. Invoked after the user has authorized the app.
        /// </summary>
        /// <param name="code"></param>
        /// <param name="state"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        public async Task<IActionResult> Callback(String code = null, Guid state = new Guid(), String scope = null)
        {
            String error;

            if (ValidateCallbackValues(code, state.ToString(), out error))
            {
                HttpRequestMessage requestMessage = new HttpRequestMessage(HttpMethod.Post, _configuration["ApplicationOAuth:RequestTokenUrl"]);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                Dictionary<String, String> form = new Dictionary<String, String>()
                {
                    { "client_id", _configuration["ApplicationOAuth:ClientID"]},
                    { "scope", _configuration["ApplicationOAuth:Scopes"]},
                    { "code", code },
                    { "redirect_uri", _configuration["ApplicationOAuth:RedirectUri"] },
                    { "grant_type", "authorization_code" },
                    { "client_secret", _configuration["ApplicationOAuth:ClientSecret"] }
                };

                requestMessage.Content = new FormUrlEncodedContent(form);

                HttpResponseMessage responseMessage = await _httpClient.SendAsync(requestMessage);

                if (responseMessage.IsSuccessStatusCode)
                {
                    String body = await responseMessage.Content.ReadAsStringAsync();

                    TokenModel tokenModel = _authorizationRequests[state];
                    JsonConvert.PopulateObject(body, tokenModel);

                    ViewBag.Token = tokenModel;
                }
                else
                {
                    error = responseMessage.ReasonPhrase;
                }
            }

            if (!String.IsNullOrEmpty(error))
                ViewBag.Error = error;

            return View("TokenView");
        }

        /// <summary>
        /// Ensures the specified auth code and state value are valid. If both are valid, the state value is marked so it can't be used again.        
        /// </summary>
        /// <param name="code"></param>
        /// <param name="state"></param>
        /// <param name="error"></param>
        /// <returns></returns>
        private static bool ValidateCallbackValues(String code, String state, out String error)
        {
            error = null;

            if (String.IsNullOrEmpty(code))
                error = "Invalid auth code";
            else
            {
                Guid authorizationRequestKey;

                if (!Guid.TryParse(state, out authorizationRequestKey))
                    error = "Invalid authorization request key";
                else
                {
                    TokenModel tokenModel;

                    if (!_authorizationRequests.TryGetValue(authorizationRequestKey, out tokenModel))
                        error = "Unknown authorization request key";
                    else if (!tokenModel.IsPending)
                        error = "Authorization request key already used";
                    else
                        _authorizationRequests[authorizationRequestKey].IsPending = false; // mark the state value as used so it can't be reused
                }
            }

            return error == null;
        }

        /// <summary>
        /// Gets a new access
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task<IActionResult> RefreshToken(string refreshToken)
        {
            String error = null;

            if (!String.IsNullOrEmpty(refreshToken))
            {
                HttpRequestMessage requestMessage = new HttpRequestMessage(HttpMethod.Post, _configuration["ApplicationOAuth:RequestTokenUrl"]);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                Dictionary<String, String> form = new Dictionary<String, String>()
                {
                    { "client_id", _configuration["ApplicationOAuth:ClientID"]},
                    { "scope", _configuration["ApplicationOAuth:Scopes"]},
                    { "refresh_token", refreshToken },
                    { "redirect_uri", _configuration["ApplicationOAuth:RedirectUri"] },
                    { "grant_type", "refresh_token" },
                    { "client_secret", _configuration["ApplicationOAuth:ClientSecret"] }
                };

                requestMessage.Content = new FormUrlEncodedContent(form);

                HttpResponseMessage responseMessage = await _httpClient.SendAsync(requestMessage);

                if (responseMessage.IsSuccessStatusCode)
                {
                    String body = await responseMessage.Content.ReadAsStringAsync();
                    var tokenModel = JObject.Parse(body).ToObject<TokenModel>();
                    JsonConvert.PopulateObject(body, tokenModel);

                    ViewBag.Token = tokenModel;
                }
                else
                    error = responseMessage.ReasonPhrase;
            }
            else
                error = "Invalid refresh token";

            if (!String.IsNullOrEmpty(error))
                ViewBag.Error = error;

            return View("TokenView");
        }
    }
}
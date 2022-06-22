using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OAuthMicrosoft.Models;
using System.Diagnostics;

namespace OAuthMicrosoft.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            ViewBag.ClientId = _configuration["ApplicationOAuth:ClientID"];
            ViewBag.ClientSecret = _configuration["ApplicationOAuth:ClientSecret"];
            ViewBag.RedirectUrl = _configuration["ApplicationOAuth:RedirectUri"];
            ViewBag.Scope = _configuration["ApplicationOAuth:Scopes"];

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using Ninject;
using System.Web.Security;
using System.Security.Principal;

namespace AuthenticationProvider.Web.Authentication
{
    public class CustomAuthentication : IAuthentication
    {
        private const string cookieName = "__AUTH_COOKIE";

        public HttpContext HttpContext { get; set; }
        public int TokenLifeTimeInHours { get; set; }

        [Inject]
        public IRepository Repository { get; set; }

        #region IAuthentication Members

        public User Login(string userName, string Password)
        {
            string hashedPassword = Repository.CalculatePasswordHash(Password);
            User retUser = Repository.Login(userName, hashedPassword);
            if (retUser != null)
            {
                CreateCookie(userName);
            }
            return retUser;
        }

        private void CreateCookie(string userName, bool isPersistent = false)
        {
            var ticket = new FormsAuthenticationTicket(
              1,
              userName,
              DateTime.Now,
              DateTime.Now.AddHours(TokenLifeTimeInHours),
              isPersistent,
              string.Empty,
              FormsAuthentication.FormsCookiePath);

            // Encrypt the ticket.
            var encTicket = FormsAuthentication.Encrypt(ticket);

            // Create the cookie.
            var AuthCookie = new HttpCookie(cookieName)
            {
                Value = encTicket,
                Expires = DateTime.Now.AddHours(TokenLifeTimeInHours)
            };
            HttpContext.Response.Cookies.Set(AuthCookie);
        }

        public void LogOut()
        {
            var httpCookie = HttpContext.Response.Cookies[cookieName];
            if (httpCookie != null)
            {
                httpCookie.Value = string.Empty;
            }
        }

        private IPrincipal _currentUser;

        public IPrincipal CurrentUser
        {
            get
            {
                if (_currentUser == null)
                {
                    try
                    {
                        HttpCookie authCookie = HttpContext.Request.Cookies.Get(cookieName);
                        if (authCookie != null && !string.IsNullOrEmpty(authCookie.Value))
                        {
                            var ticket = FormsAuthentication.Decrypt(authCookie.Value);
                            _currentUser = new UserProvider(ticket.Name, Repository);
                        }
                        else
                        {
                            //_currentUser = new UserProvider(HttpContext.Request.UserHostAddress, Repository, true);
                            _currentUser = new UserProvider(null, Repository, true);
                        }
                    }
                    catch (Exception ex)
                    {                      
                        Utils.LoggingUtils.DefaultLogger.AddLogMessage("AuthenticationProvider", Utils.MessageType.Error, 
                            "Failed authentication. Application: {0}. Message:{1}", HttpContext.Application.ToString(), ex.Message);
                        _currentUser = new UserProvider(null, null);
                    }
                }
                return _currentUser;
            }
        }
        #endregion
    }
}

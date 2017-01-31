using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Mvc;
using AuthenticationProvider.Web.Authentication;
using Utils;

namespace AuthenticationProvider.Filters
{
    public class SecurableActionAttribute:AuthorizeAttribute
    {
        public SecurableActionAttribute(bool publicAccess = false)
        {
            _publicAccess = publicAccess;
        }

        protected override bool AuthorizeCore(System.Web.HttpContextBase httpContext)
        {
            var repo = ((IUserProvider)httpContext.User.Identity).Repository;
            var action = httpContext.Request.RequestContext.RouteData.GetRequiredString("action");
            var controller = httpContext.Request.RequestContext.RouteData.GetRequiredString("controller");
            if (httpContext.User != null && httpContext.User.Identity.Name != "anonym")
            {
                var user = ((IUserProvider)httpContext.User.Identity).User;
                
                return repo.IsUserHasPermission(user.Id, controller, action);
            }
            else if(_publicAccess)
            {                
                var ipAddress = httpContext.Request.UserHostAddress;
                return repo.IsUserHasAccess(ipAddress, controller, action);
            }

            return false;
        }

        private bool _publicAccess;
    }
}

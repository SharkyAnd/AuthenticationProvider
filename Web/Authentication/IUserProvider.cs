using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AuthenticationProvider.Web.Authentication
{
    public interface IUserProvider
    {
        User User { get; set; }
        IRepository Repository { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;

namespace AuthenticationProvider.Web.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public class UserProvider : IPrincipal, IUserProvider
    {
        private UserIndentity userIdentity { get; set; }

        #region IPrincipal Members

        /// <summary>
        /// 
        /// </summary>
        public IIdentity Identity
        {
            get
            {
                return userIdentity;
            }
        }

        /// <summary>
        /// Determine if user has role
        /// </summary>
        /// <param name="role">Role name</param>
        /// <returns></returns>
        public bool IsInRole(string role)
        {
            if (userIdentity.User == null)
            {
                return false;
            }

            return userIdentity.User.InRoles(role, Repository);
        }

        #endregion

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">User name or password</param>
        /// <param name="repository">User repository instance</param>
        /// <param name="publicAccess">Public access</param>
        public UserProvider(string name, IRepository repository, bool publicAccess = false)
        {
            userIdentity = new UserIndentity();
            Repository = repository;
            userIdentity.Init(name, Repository, publicAccess);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return userIdentity.Name;
        }

        public User User
        {
            get;
            set;
        }

        public IRepository Repository
        {
            get;
            set;
        }
    }
}

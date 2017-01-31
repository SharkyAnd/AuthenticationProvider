using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;

namespace AuthenticationProvider.Web.Authentication
{
    [Serializable]
    public class UserIndentity : MarshalByRefObject, IIdentity, IUserProvider
    {
        /// <summary>
        /// 
        /// </summary>
        public User User { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string AuthenticationType
        {
            get
            {
                return typeof(User).ToString();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public bool IsAuthenticated
        {
            get
            {
                return User != null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public string Name
        {
            get
            {
                if (User != null)
                {
                    return User.UserName == null ? User.Email : User.UserName;
                }
                //иначе аноним
                return "anonym";
            }
        }

        /// <summary>
        /// User initialization
        /// </summary>
        /// <param name="login">User name or email</param>
        /// <param name="repository">Instance of repository</param>
        /// <param name="publicAccess">Public access</param>
        public void Init(string login, IRepository repository, bool publicAccess = false)
        {
            Repository = repository;
            if (!string.IsNullOrEmpty(login))
            {
                User = Repository.GetUser(login);
            }
        }


        public IRepository Repository
        {
            get;
            set;
        }
    }
}

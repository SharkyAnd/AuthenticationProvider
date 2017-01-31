using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using AuthenticationProvider.Models;

namespace AuthenticationProvider
{
    public interface IRepository
    {
        #region Role
        /// <summary>
        /// Get information of all roles
        /// </summary>
        /// <returns>Roles</returns>
        IEnumerable<Role> GetRoles();
        /// <summary>
        /// Get all roles names
        /// </summary>
        /// <returns>Array of names</returns>
        string[] GetRolesNames();
        /// <summary>
        /// Create new role
        /// </summary>
        /// <param name="instance">New role instance</param>
        /// <returns>Result</returns>
        bool CreateRole(Role instance);
        /// <summary>
        /// Update Role
        /// </summary>
        /// <param name="instance">Role instance</param>
        /// <returns>Result</returns>
        bool UpdateRole(Role instance);
        /// <summary>
        /// Remove Role
        /// </summary>
        /// <param name="idRole">Id of the role</param>
        /// <returns>Result</returns>
        bool RemoveRole(int idRole);
        bool AddRolePermissions(string roleName, string controller, string action);
        #endregion

        #region User
        /// <summary>
        /// Get information of all users
        /// </summary>
        /// <returns>Users</returns>
        IEnumerable<User> GetUsers();
        /// <summary>
        /// Get all users names
        /// </summary>
        /// <returns>Array of names</returns>
        string[] GetUserNames();
        /// <summary>
        /// Create new user
        /// </summary>
        /// <param name="instance">User instance</param>
        /// <returns>Result</returns>
        int CreateUser(User instance);
        /// <summary>
        /// Update user
        /// </summary>
        /// <param name="instance">User instance</param>
        /// <returns>Result</returns>
        bool UpdateUser(User instance);
        /// <summary>
        /// Remove user
        /// </summary>
        /// <param name="idUser">Id of the user</param>
        /// <returns>Result</returns>
        bool RemoveUser(int idUser);
        /// <summary>
        /// Get user information by its login
        /// </summary>
        /// <param name="login">Login</param>
        /// <returns>User instance</returns>
        User GetUser(string login);
        /// <summary>
        /// Login using name and password
        /// </summary>
        /// <param name="login">Login</param>
        /// <param name="password">Password</param>
        /// <returns>User instance</returns>
        User Login(string login,string password);
        /// <summary>
        /// Calculate hash for the password
        /// </summary>
        /// <param name="password">Password</param>
        /// <returns>Hash</returns>
        string CalculatePasswordHash(string password);
        /// <summary>
        /// Check if user in roles
        /// </summary>
        /// <param name="roles">Roles separated by comma</param>
        /// <param name="userName">User name</param>
        /// <returns></returns>
        bool InRoles(string roles, string userName);

        #endregion

        #region UserRole
        /// <summary>
        /// Get information about users and associated roles
        /// </summary>
        /// <returns>Users-roles instance</returns>
        IEnumerable<UserRole> GetUsersRoles();
        /// <summary>
        /// Add user to role
        /// </summary>
        /// <param name="instance">User-role instance</param>
        /// <returns>Result</returns>
        bool CreateUserRole(UserRole instance);
        /// <summary>
        /// Update user-role instance
        /// </summary>
        /// <param name="instance">User-role instance</param>
        /// <returns>Result</returns>
        bool UpdateUserRole(UserRole instance);
        /// <summary>
        /// Remove user from role
        /// </summary>
        /// <param name="idUserRole">Id of user-role instance</param>
        /// <returns>Result</returns>
        bool RemoveUserRole(string userName, string roleName);
        /// <summary>
        /// Get all permissions
        /// </summary>
        /// <returns>Array of permissions</returns>
        string[] GetPermissions();

        #endregion 

        #region Activation
        /// <summary>
        /// Activate account
        /// </summary>
        /// <param name="activationCode">Activation code</param>
        /// <returns>Result</returns>
        bool ActivateAccount(string activationCode);
        /// <summary>
        /// Add new activation code
        /// </summary>
        /// <param name="activationCode">Activation code</param>
        /// <param name="senderUserName">User name that send activation email</param>
        /// <param name="recieverUserName">User name recieves activation email</param>
        /// <returns>Result</returns>
        bool AddActivationCode(string activationCode, string senderUserName, string recieverUserName);
        /// <summary>
        /// Send account confirmation email
        /// </summary>
        /// <param name="confirmationDataModel">Confirmation data</param>
        /// <param name="applicationName">Application name</param>
        /// <param name="applicationAddress">Application registration base url</param>
        /// <returns>Result</returns>
        bool SendConfirmationEmail(ConfirmationDataModel confirmationDataModel, string applicationName, string applicationAddress);
        #endregion

        #region Permissions
        /// <summary>
        /// Synchronizes permissions list with Database
        /// </summary>
        /// <param name="executingAssembly">Instance of assembly where permissions are</param>
        void SynchronizeWebPermissions(Assembly executingAssembly);
        /// <summary>
        /// Determines if user have access to the action
        /// </summary>
        /// <param name="userId">Id of the user</param>
        /// <param name="controller">Controller name</param>
        /// <param name="action">Action name</param>
        /// <returns></returns>
        bool IsUserHasPermission(int userId, string controller, string action);
        /// <summary>
        /// Gets list of controllers and their actions
        /// </summary>
        /// <returns></returns>
        IEnumerable<ActionsByControllers> GetActionsByControllers();
        #endregion

        #region Public access
        /// <summary>
        /// Determines if requested ip address have access to the action
        /// </summary>
        /// <param name="ipAddress">Ip address</param>
        /// <param name="controller">Controller name</param>
        /// <param name="action">Action name</param>
        /// <returns></returns>
        bool IsUserHasAccess(string ipAddress, string controller, string action);
        /// <summary>
        /// Get information of all public access rules
        /// </summary>
        /// <returns>Roles</returns>
        IEnumerable<Rule> GetRules();
        /// <summary>
        /// Create new public access rule
        /// </summary>
        /// <param name="instance">New rule instance</param>
        /// <returns>Result</returns>
        bool CreateRule(Rule instance);
        /// <summary>
        /// Update public access rule
        /// </summary>
        /// <param name="instance">Rule instance</param>
        /// <returns>Result</returns>
        bool UpdateRule(Rule instance);
        /// <summary>
        /// Remove public access rule
        /// </summary>
        /// <param name="idRole">Id of the rule</param>
        /// <returns>Result</returns>
        bool RemoveRule(int idRule);
        /// <summary>
        /// Adding new record about rule permissions
        /// </summary>
        /// <param name="ruleName">Mask of the rule</param>
        /// <param name="controller">Controller name</param>
        /// <param name="action">Action name</param>
        /// <returns></returns>
        bool AddRulePermissions(string ruleName, string controller, string action);
        #endregion
    }
}

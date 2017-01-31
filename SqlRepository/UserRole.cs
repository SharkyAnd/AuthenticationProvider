using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;
using System.Data.SqlClient;

namespace AuthenticationProvider
{
    public partial class SqlRepository
    {
        public IEnumerable<UserRole> GetUsersRoles()
        {
            string query = @"SELECT ur.Id, u.UserName, r.Name FROM UsersRoles ur
                                INNER JOIN WebUsers u ON ur.UserId = u.Id
                                INNER JOIN Roles r ON ur.RoleId = r.Id";

            DataTable dt = DB.ExecuteDataTable(query, null);

            return dt.AsEnumerable().Select(r => new UserRole
            {
                Id = Convert.ToInt32(r["Id"]),
                UserName = r["UserName"].ToString(),
                RoleName = r["UserName"].ToString()
            });
        }

        public bool CreateUserRole(UserRole instance)
        {
            if (CheckUserRoleExistings(instance) == -1)
            {
                string query = @"INSERT INTO UsersRoles (UserId, RoleId)
                                VALUES((SELECT TOP 1 Id FROM WebUsers WHERE UserName = @UserName), 
                                (SELECT TOP 1 Id FROM Roles WHERE Name = @RoleName))";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@UserName", instance.UserName},
                    {"@RoleName", instance.RoleName}
                });
                return true;
            }

            return false;
        }

        public bool UpdateUserRole(UserRole instance)
        {
            int userRoleId = CheckUserRoleExistings(instance);

            if (userRoleId != -1)
            {
                string query = @"UPDATE UsersRoles SET
                                UserId = (SELECT TOP 1 UserId FROM WebUsers WHERE UserName = @UserName), 
                                RoleId = (SELECT TOP 1 RoleId FROM Roles WHERE Name = @RoleName)";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@UserName", instance.UserName},
                    {"@RoleName", instance.RoleName}
                });
                return true;
            }

            return false;
        }

        public bool RemoveUserRole(string userName, string roleName)
        {
            if (CheckUserRoleExistings(userName, roleName))
            {
                string query = @"DELETE FROM UsersRoles WHERE 
                                UserId = (SELECT TOP 1 Id FROM WebUsers WHERE Name = @UserName) AND 
                                RoleId = (SELECT TOP 1 Id FROM Roles WHERE Name = @RoleName)";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@UserName", userName},
                    {"@RoleName", roleName}
                });
                return true;
            }

            return false;
        }

        private int CheckUserRoleExistings(UserRole instance)
        {
            int userRoleId = -1;
            DB.ExecuteRead(@"SELECT ur.Id FROM UsersRoles ur INNER JOIN WebUsers u ON ur.UserId = u.id INNER JOIN Roles r ON ur.RoleId = r.id WHERE u.UserName = @UserName AND r.Name = @RoleName",
                new Dictionary<string, object> { { "@UserName", instance.UserName }, { "@RoleName", instance.RoleName } }, delegate(SqlDataReader sdr)
                {
                    userRoleId = sdr.GetInt32(0);
                }, -1);

            return userRoleId;
        }

        private bool CheckUserRoleExistings(string userName, string roleName)
        {
            string query = @"SELECT DISTINCT * FROM UsersRoles WHERE
                            UserId = (SELECT TOP 1 Id FROM WebUsers WHERE Name = @UserName) AND 
                            RoleId = (SELECT TOP 1 Id FROM Roles WHERE Name = @RoleName)";

            DataTable dt = DB.ExecuteDataTable(query, new Dictionary<string, object> { { "@UserName", userName }, {"@RoleName", roleName} });

            if (dt.Rows.Count > 0)
                return true;

            return false;
        }
    }
}

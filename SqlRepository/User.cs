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
        private const string salt = "04B472BA43FEB5B6";

        public IEnumerable<User> GetUsers()
        {
            string query = @"SELECT DISTINCT u.id, u.UserName, u.Email, u.LastVisitDate, u.AddedDate, cm.Activated
                             FROM WebUsers u 
                             LEFT JOIN ConfirmationMails cm ON u.Id = cm.RecieverUserId AND Activated = 1
                             order by u.UserName";

            DataTable dt = DB.ExecuteDataTable(query, null);

            return dt.AsEnumerable().Select(r => new User
            {
                Id = Convert.ToInt32(r["Id"]),
                UserName = r["UserName"].ToString(),
                Email = r["Email"] == DBNull.Value ? "" : r["Email"].ToString(),
                AddedDate = r["AddedDate"] == DBNull.Value ? (DateTime?)null : Convert.ToDateTime(r["AddedDate"]),
                LastVisitDate = r["LastVisitDate"] == DBNull.Value ? (DateTime?)null : Convert.ToDateTime(r["LastVisitDate"]),
                Confirmed = r["Activated"] == DBNull.Value ? false : Convert.ToBoolean(r["Activated"])
            });
        }

        public string[] GetUserNames()
        {
            string query = @"SELECT DISTINCT UserName FROM WebUsers order by UserName";

            DataTable dt = DB.ExecuteDataTable(query, null);

            return dt.AsEnumerable().Select(r => r["UserName"].ToString()).ToArray();
        }

        public int CreateUser(User instance)
        {
            int userId = CheckUserExistings(instance);
            if (userId == -1)
            {
                userId = Convert.ToInt32(DB.InsertNewRowAndGetItsId("WebUsers", new Dictionary<string, object>
                {
                    {"UserName", instance.UserName},
                    {"Email", instance.Email},
                    {"AddedDate", DateTime.Now},
                    {"PasswordHash", instance.Password}
                }, true));
            }

            return userId;
        }

        public bool IsUserHasPermission(int userId, string controller, string action)
        {
            int userRoleId = -1;

            DB.ExecuteRead(@"SELECT pbr.Id FROM UsersRoles ur 
                                INNER JOIN WebUsers u ON ur.UserId = u.id 
                                INNER JOIN Roles r ON ur.RoleId = r.id 
                                INNER JOIN PermissionsByRoles pbr ON pbr.RoleId = r.Id
                                INNER JOIN Permissions p ON pbr.PermissionId = p.Id
                                WHERE u.Id = @UserId AND p.Controller = @Controller AND p.Action = @Action",
                new Dictionary<string, object> { { "@UserId", userId }, { "@Controller", controller }, {"@Action", action} }, delegate(SqlDataReader sdr)
                {
                    userRoleId = sdr.GetInt32(0);
                }, -1);

            if (userRoleId != -1)
                return true;
            return false;
        }

        public bool InRoles(string roles, string userName)
        {
            var rolesArray = roles.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var role in rolesArray)
            {

                int userRoleId = -1;

                DB.ExecuteRead(@"SELECT pbr.Id FROM UsersRoles ur 
                                INNER JOIN WebUsers u ON ur.UserId = u.id 
                                INNER JOIN Roles r ON ur.RoleId = r.id 
                                INNER JOIN PermissionsByRoles pbr ON pbr.RoleId = r.Id
                                INNER JOIN Permissions p ON pbr.PermissionId = p.Id
                                WHERE (u.UserName = @UserName OR u.Email = @UserName) AND p.Name = @RoleName",
                    new Dictionary<string, object> { { "@UserName", userName }, { "@RoleName", role } }, delegate(SqlDataReader sdr)
                    {
                        userRoleId = sdr.GetInt32(0);
                    }, -1);

                if (userRoleId != -1)
                    return true;
            }
            return false;
        }

        public bool UpdateUser(User instance)
        {
            if (CheckUserExistings(instance.Id))
            {
                string query = @"UPDATE WebUsers SET UserName = @UserName, Email = @Email" + (instance.Password != null ? ", PasswordHash = @PasswordHash" : "") + " WHERE Id = @Id";
                Dictionary<string, object> parameters = new Dictionary<string, object> { { "@Email", instance.Email }, { "@UserName", instance.UserName }, { "@Id", instance.Id } };
                if (instance.Password != null)
                    parameters.Add("@PasswordHash", instance.Password);
                DB.ExecuteScalarQuery(query, parameters);
                return true;
            }
            return false;
        }

        public bool RemoveUser(int idUser)
        {
            if (CheckUserExistings(idUser))
            {
                string query = @"DELETE FROM UsersRoles WHERE UserId = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idUser}
                });

                query = @"DELETE FROM ConfirmationMails WHERE RecieverUserId = @Id OR SenderUserId = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idUser}
                });

                query = @"DELETE FROM WebUsers WHERE Id = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idUser}
                });
                return true;
            }

            return false;
        }

        private int CheckUserExistings(User user)
        {
            int userId = -1;
            DB.ExecuteRead(@"SELECT Id FROM WebUsers WHERE Email = @Email OR UserName = @UserName",
                new Dictionary<string, object> { { "@Email", user.Email }, { "@UserName", user.UserName } }, delegate(SqlDataReader sdr)
                {
                    userId = sdr.GetInt32(0);
                }, -1);

            return userId;
        }

        private bool CheckUserExistings(int userId)
        {
            string query = @"SELECT DISTINCT * FROM WebUsers WHERE Id = @UserId";

            DataTable dt = DB.ExecuteDataTable(query, new Dictionary<string, object> { { "@UserId", userId } });

            if (dt.Rows.Count > 0)
                return true;

            return false;
        }

        public User GetUser(string login)
        {
            User user = new User();

            DB.ExecuteRead(@"SELECT Id, UserName, Email, LastVisitDate FROM WebUsers WHERE Email = @Login OR UserName = @Login",
                new Dictionary<string, object> { { "@Login", login } }, delegate(SqlDataReader sdr)
                            {
                                user.Id = sdr.GetInt32(0);
                                user.UserName = sdr.GetString(1);
                                user.Email = sdr.GetValue(2) == DBNull.Value ? null : sdr.GetString(2);
                                user.LastVisitDate = sdr.GetValue(3) == DBNull.Value ? DateTime.MinValue : sdr.GetDateTime(3);
                            }, -1);

            return user;
        }

        public User Login(string login, string passwordHash)
        {
            User user = new User();

            DB.ExecuteRead(@"SELECT Id, UserName, Email, LastVisitDate FROM WebUsers WHERE (Email = @Login OR UserName = @Login) AND PasswordHash = @PasswordHash",
                new Dictionary<string, object> { { "@Login", login }, { "@PasswordHash", passwordHash } }, delegate(SqlDataReader sdr)
                {
                    user.Id = sdr.GetInt32(0);
                    user.UserName = sdr.GetString(1);
                    user.Email = sdr.GetValue(2) == DBNull.Value ? null : sdr.GetString(2);
                    user.LastVisitDate = sdr.GetValue(3) == DBNull.Value ? DateTime.MinValue : sdr.GetDateTime(3);
                }, -1);

            if (user.Id == 0)
                return null;
            DB.ExecuteScalarQuery(@"UPDATE WebUsers SET LastVisitDate = GETDATE() WHERE Id = @UserId", new Dictionary<string, object>
                {
                    {"@UserId", user.Id}
                });

            return user;
        }

        public string CalculatePasswordHash(string password)
        {
            BlowFishCS.BlowFish b = new BlowFishCS.BlowFish(salt);

            return b.Encrypt_ECB(password);
        }
    }
}

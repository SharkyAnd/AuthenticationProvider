using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;
using System.Web;

namespace AuthenticationProvider.Web.Authentication
{
    public interface IAuthentication
    {
        /// <summary>
        /// Конекст (тут мы получаем доступ к запросу и кукисам)
        /// </summary>
        HttpContext HttpContext { get; set; }
        int TokenLifeTimeInHours { get; set; }
        /// <summary>
        /// Процедура входа
        /// </summary>
        /// <param name="login">логин</param>
        /// <param name="password">пароль</param>
        /// <param name="isPersistent">постоянная авторизация или нет</param>
        /// <returns></returns>
        User Login(string login, string password);

        /// <summary>
        /// Выход
        /// </summary>
        void LogOut();

        /// <summary>
        /// Данные о текущем пользователе
        /// </summary>
        IPrincipal CurrentUser { get; }
    }
}

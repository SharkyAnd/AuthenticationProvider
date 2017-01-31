using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Mvc.Html;
using AuthenticationProvider.Web.Authentication;

namespace AuthenticationProvider.Web.Helpers
{
    public static class HtmlHelperExtensions
    {
        public static HttpContextBase GetContext(this HtmlHelper htmlHelper)
        {
            return htmlHelper.ViewContext.HttpContext;
        }

        public static MvcHtmlString SecurableLink(this HtmlHelper html, string innerText, string action, string controller, bool publicAccess = false)
        {
            try
            {
                var httpContext = GetContext(html);
                bool createLink = false;
                var repo = ((IUserProvider)httpContext.User.Identity).Repository;
                if (httpContext.User != null && httpContext.User.Identity.Name != "anonym")
                {
                    var user = ((IUserProvider)httpContext.User.Identity).User;

                    if (repo.IsUserHasPermission(user.Id, controller, action))
                        createLink = true;
                }
                else if (publicAccess && repo.IsUserHasAccess(httpContext.Request.UserHostAddress, controller, action))
                    createLink = true;


                if (createLink)
                {
                    UrlHelper helper = new UrlHelper(httpContext.Request.RequestContext);
                    var actionUrl = helper.Action(action, controller);

                    var liBuilder = new TagBuilder("li");
                    var aBuilder = new TagBuilder("a");

                    aBuilder.MergeAttribute("href", actionUrl);
                    aBuilder.MergeAttribute("class", "navbar-link");
                    aBuilder.SetInnerText(innerText);

                    liBuilder.InnerHtml = aBuilder.ToString();

                    return new MvcHtmlString(liBuilder.ToString(TagRenderMode.Normal));
                }
            }
            catch (Exception ex)
            {
                return null;
            }

            return null;
        }

        public static MvcHtmlString SecurableSubMenu(this HtmlHelper html, string subMenuName, List<MvcHtmlString> actions)
        {
            actions.RemoveAll(a => a == null);
            if (actions.Count == 0)
                return null;

            var dropdownSubMenuT = new TagBuilder("li");
            dropdownSubMenuT.AddCssClass("dropdown-submenu");

            var subMenuNameT = new TagBuilder("a");
            subMenuNameT.MergeAttribute("tabindex", "-1");
            subMenuNameT.MergeAttribute("href", "#");
            subMenuNameT.SetInnerText(subMenuName);

            dropdownSubMenuT.InnerHtml += subMenuNameT.ToString(TagRenderMode.Normal);

            var dropdownMenuT = new TagBuilder("ul");
            dropdownMenuT.AddCssClass("dropdown-menu");

            foreach (MvcHtmlString action in actions)
            {
                dropdownMenuT.InnerHtml += action.ToHtmlString();
            }

            dropdownSubMenuT.InnerHtml += dropdownMenuT;

            return new MvcHtmlString(dropdownSubMenuT.ToString(TagRenderMode.Normal));
        }

        public static MvcHtmlString SecurableMenu(this HtmlHelper html, string menuName, List<MvcHtmlString> subMenus = null, List<MvcHtmlString> actions = null)
        {
            if (subMenus == null)
                subMenus = new List<MvcHtmlString>();
            if (actions == null)
                actions = new List<MvcHtmlString>();

            actions.RemoveAll(a => a == null);
            subMenus.RemoveAll(s => s == null);

            if (actions.Count == 0 && subMenus.Count == 0)
                return null;

            var dropdownMenuT = new TagBuilder("li");
            dropdownMenuT.AddCssClass("dropdown");

            var menuNameT = new TagBuilder("a");
            menuNameT.AddCssClass("dropdown-toggle");
            menuNameT.MergeAttribute("data-toggle", "dropdown");
            menuNameT.MergeAttribute("href", "#");
            menuNameT.SetInnerText(menuName);

            var caretT = new TagBuilder("span");
            caretT.AddCssClass("caret");

            menuNameT.InnerHtml += caretT.ToString(TagRenderMode.Normal);
            dropdownMenuT.InnerHtml += menuNameT.ToString(TagRenderMode.Normal);

            var dropdownMenuListT = new TagBuilder("ul");
            dropdownMenuListT.AddCssClass("dropdown-menu");

            foreach (MvcHtmlString subMenu in subMenus)
            {
                dropdownMenuListT.InnerHtml += subMenu.ToHtmlString();
            }

            foreach (MvcHtmlString action in actions)
            {
                dropdownMenuListT.InnerHtml += action.ToHtmlString();
            }

            dropdownMenuT.InnerHtml += dropdownMenuListT.ToString(TagRenderMode.Normal);

            return new MvcHtmlString(dropdownMenuT.ToString(TagRenderMode.Normal)); ;
        }
    }
}

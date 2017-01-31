using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AuthenticationProvider.Models;
using System.Net.Mail;
using Utils;
using System.Net;

namespace AuthenticationProvider
{
    public partial class SqlRepository
    {
        /// <summary>
        /// Add activation code to account
        /// </summary>
        /// <param name="activationCode">Activation code</param>
        /// <param name="senderUserName"></param>
        /// <param name="recieverUserName"></param>
        /// <returns></returns>
        public bool AddActivationCode(string activationCode, string senderUserName, string recieverUserName)
        {
            string query = @"INSERT INTO ConfirmationMails (ActivationCode, SenderUserId, RecieverUserId, SendDate)
                             VALUES(@ActivationCode, (SELECT Id FROM WebUsers WHERE UserName = @SenderUserName OR Email = @SenderUserName),
                            (SELECT Id FROM WebUsers WHERE UserName = @RecieverUserName OR Email = @RecieverUserName), 
                            GETDATE())";

            DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@ActivationCode", activationCode},
                    {"@SenderUserName", senderUserName},
                    {"@RecieverUserName", recieverUserName}
                });
            return true;
        }
        /// <summary>
        /// Activate user account
        /// </summary>
        /// <param name="activationCode">Activation code</param>
        /// <returns></returns>
        public bool ActivateAccount(string activationCode)
        {
            string query = @"UPDATE ConfirmationMails SET Activated = 1, ActivateDate = GETDATE() WHERE ActivationCode = @ActivationCode";

            DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@ActivationCode", activationCode}
                });
            return true;
        }
        /// <summary>
        /// Send confirmation email
        /// </summary>
        /// <param name="confirmationDataModel">Confirmation data</param>
        /// <param name="applicationName">Application name</param>
        /// <param name="returnUrl">Url to activate account</param>
        /// <returns></returns>
        public bool SendConfirmationEmail(ConfirmationDataModel confirmationDataModel, string applicationName, string returnUrl)
        {
            try
            {
                string message = "You were added to "+applicationName+ " Users. "+
                "Proceed the following link to complete your registration "+returnUrl+"Account/Register?";
                string paramsMessage = null;
                List<object> parameters = new List<object> 
                { 
                    confirmationDataModel.UserName == null ? confirmationDataModel.Email : confirmationDataModel.UserName, 
                    confirmationDataModel.ActivationCode 
                };
                message += "Login=" + (confirmationDataModel.UserName == null ? confirmationDataModel.Email : confirmationDataModel.UserName) +
                    "&ActivationCode=" + confirmationDataModel.ActivationCode + "";
                if (confirmationDataModel.AssociatedRoles != null)
                {
                    paramsMessage += "\nAfter registration you will be associated with the following roles: " + confirmationDataModel.AssociatedRoles + "";
                }


                string SmtpHost = "smtp.gmail.com";

                string FromAddress = "your_address@gmail.com";

                string FromName = "";

                string subject = ""+applicationName+". Account confirmation";

                string Recipients = confirmationDataModel.Email;

                string body = message + paramsMessage;

                using (SmtpClient client = new SmtpClient(SmtpHost))
                {
                    client.Credentials = new NetworkCredential("username", "pass");
                    client.EnableSsl = true;

                    MailMessage mailMessage = new MailMessage();
                    mailMessage.From = new MailAddress(FromAddress, FromName);
                    mailMessage.To.Add(Recipients);

                    mailMessage.Subject = subject;
                    mailMessage.Body = body;

                    client.Send(mailMessage);
                }
                return false;
            }
            catch (Exception ex)
            {
                Utils.LoggingUtils.DefaultLogger.AddLogMessage("DevelopmentDashboard", MessageType.Error, "Error while trying to send email. Message: {0}", ex.Message);
                return false;
            }
        }
    }
}

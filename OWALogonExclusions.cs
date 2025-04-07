using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using Microsoft.Win32;
using System.Management;
using System.Reflection;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Security;
using System.Security.Cryptography;
using ActiveDs;

namespace OWALogonExclusions
{
    public class Sentinel
    {
        public Sentinel()
        {
        }

        public string strData;

        public void funcProtect(string strPackage)
        {
            strData = Encrypt(strPackage);
        }

        public void funcServe(string strPackage)
        {
            strData = Decrypt(strPackage);
        }

        private string Encrypt(string input)
        {
            return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(input)));
        }

        private byte[] Encrypt(byte[] input)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes("hjiweykaksd", new byte[] { 0x43, 0x87, 0x23, 0x72, 0x45, 0x56, 0x68, 0x14, 0x62, 0x84 });
            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }

        private string Decrypt(string input)
        {
            return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(input)));
        }

        private byte[] Decrypt(byte[] input)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes("hjiweykaksd", new byte[] { 0x43, 0x87, 0x23, 0x72, 0x45, 0x56, 0x68, 0x14, 0x62, 0x84 });
            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }
    }

    class OLEMain
    {
        struct CMDArguments
        {
            public bool bParseCmdArguments;
        }

        struct OWALogonParams
        {
            public string strOWALogFileLocation;
            public string strExclusionGroupLocation;
        }

        static bool funcLicenseCheck()
        {
            try
            {
                string strLicenseString = "";
                bool bValidLicense = false;

                TextReader tr = new StreamReader("sotfwlic.dat");

                try
                {
                    strLicenseString = tr.ReadLine();

                    if (strLicenseString.Length > 0 & strLicenseString.Length < 29)
                    {
                        // [DebugLine] Console.WriteLine("if: " + strLicenseString);
                        Console.WriteLine("Invalid license");

                        tr.Close(); // close license file

                        return bValidLicense;
                    }
                    else
                    {
                        tr.Close(); // close license file
                        // [DebugLine] Console.WriteLine("else: " + strLicenseString);

                        string strMonthTemp = ""; // to convert the month into the proper number
                        string strDate;

                        //Month
                        strMonthTemp = strLicenseString.Substring(7, 1);
                        if (strMonthTemp == "A")
                        {
                            strMonthTemp = "10";
                        }
                        if (strMonthTemp == "B")
                        {
                            strMonthTemp = "11";
                        }
                        if (strMonthTemp == "C")
                        {
                            strMonthTemp = "12";
                        }
                        strDate = strMonthTemp;

                        //Day
                        strDate = strDate + "/" + strLicenseString.Substring(16, 1);
                        strDate = strDate + strLicenseString.Substring(6, 1);

                        // Year
                        strDate = strDate + "/" + strLicenseString.Substring(24, 1);
                        strDate = strDate + strLicenseString.Substring(4, 1);
                        strDate = strDate + strLicenseString.Substring(1, 2);

                        // [DebugLine] Console.WriteLine(strDate);
                        // [DebugLine] Console.WriteLine(DateTime.Today.ToString());
                        DateTime dtLicenseDate = DateTime.Parse(strDate);
                        // [DebugLine]Console.WriteLine(dtLicenseDate.ToString());

                        if (dtLicenseDate >= DateTime.Today)
                        {
                            bValidLicense = true;
                        }
                        else
                        {
                            Console.WriteLine("License expired.");
                        }

                        return bValidLicense;
                    }

                } //end of try block on tr.ReadLine

                catch
                {
                    // [DebugLine] Console.WriteLine("catch on tr.Readline");
                    Console.WriteLine("Invalid license");
                    tr.Close();
                    return bValidLicense;

                } //end of catch block on tr.ReadLine

            } // end of try block on new StreamReader("sotfwlic.dat")

            catch (System.Exception ex)
            {
                // [DebugLine] System.Console.WriteLine("{0} exception caught here.", ex.GetType().ToString());

                // [DebugLine] System.Console.WriteLine(ex.Message);

                if (ex.Message.StartsWith("Could not find file"))
                {
                    Console.WriteLine("License file not found.");
                }
                else
                {
                    MethodBase mb1 = MethodBase.GetCurrentMethod();
                    funcGetFuncCatchCode(mb1.Name, ex);
                }

                return false;

            } // end of catch block on new StreamReader("sotfwlic.dat")
        }

        static bool funcPortableLicenseCheck()
        {
            try
            {
                string strPortableLicense = String.Empty;

                if (funcCheckForFile("SystemsAdminPro.app"))
                {
                    TextReader trPortableLicense = new StreamReader("SystemsAdminPro.app");
                    strPortableLicense = trPortableLicense.ReadLine();
                    trPortableLicense.Close();

                    Domain dmCurrent = Domain.GetCurrentDomain();
                    DirectoryEntry domainDE = dmCurrent.GetDirectoryEntry();
                    Guid dmGUID = domainDE.Guid;
                    //[DebugLine] Console.WriteLine(dmGUID.ToString());
                    Sentinel newSentinel = new Sentinel();
                    newSentinel.funcServe(strPortableLicense);
                    if (dmGUID.ToString() == newSentinel.strData)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                return false;
            }
        }

        static void funcPrintParameterWarning()
        {
            Console.WriteLine("A parameter is missing or is incorrect.");
            Console.WriteLine("Run OWALogonExclusions -? to get the parameter syntax.");
        }

        static void funcPrintParameterSyntax()
        {
            Console.WriteLine("OWALogonExclusions v1.0 (c) 2011 SystemsAdminPro.com");
            Console.WriteLine();
            Console.WriteLine("Description: Find OWA logons and create exclusions");
            Console.WriteLine();
            Console.WriteLine("Parameter syntax:");
            Console.WriteLine();
            Console.WriteLine("Use the following required parameters in the following order:");
            Console.WriteLine("-run                     required parameter");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine("OWALogonExclusions -run");
        }

        static CMDArguments funcParseCmdArguments(string[] cmdargs)
        {
            CMDArguments objCMDArguments = new CMDArguments();

            try
            {
                if (cmdargs[0] == "-run" & cmdargs.Length == 1)
                {
                    objCMDArguments.bParseCmdArguments = true;
                }
                else
                {
                    objCMDArguments.bParseCmdArguments = false;
                }
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                objCMDArguments.bParseCmdArguments = false;
            }

            return objCMDArguments;
        }

        static OWALogonParams funcParseConfigFile(CMDArguments objCMDArguments2)
        {
            OWALogonParams newParams = new OWALogonParams();

            TextReader trConfigFile = new StreamReader("configOWALogonExclusions.txt");

            using (trConfigFile)
            {
                string strNewLine = "";

                while ((strNewLine = trConfigFile.ReadLine()) != null)
                {

                    if (strNewLine.StartsWith("OWALogFileLocation="))
                    {
                        newParams.strOWALogFileLocation = strNewLine.Substring(19);
                        //[DebugLine] Console.WriteLine(newParams.strOWALogFileLocation);
                    }
                    if (strNewLine.StartsWith("ExclusionGroupLocation="))
                    {
                        newParams.strExclusionGroupLocation = strNewLine.Substring(23);
                        //[DebugLine] Console.WriteLine(newParams.strExclusionGroupLocation);
                    }
                }
            }

            //[DebugLine] Console.WriteLine("# of Exclude= : {0}", newParams.lstExclude.Count.ToString());
            //[DebugLine] Console.WriteLine("# of ExcludePrefix= : {0}", newParams.lstExcludePrefix.Count.ToString());

            trConfigFile.Close();

            return newParams;
        }

        static void funcProgramRegistryTag(string strProgramName)
        {
            try
            {
                string strRegistryProfilesPath = "SOFTWARE";
                RegistryKey objRootKey = Microsoft.Win32.Registry.LocalMachine;
                RegistryKey objSoftwareKey = objRootKey.OpenSubKey(strRegistryProfilesPath, true);
                RegistryKey objSystemsAdminProKey = objSoftwareKey.OpenSubKey("SystemsAdminPro", true);
                if (objSystemsAdminProKey == null)
                {
                    objSystemsAdminProKey = objSoftwareKey.CreateSubKey("SystemsAdminPro");
                }
                if (objSystemsAdminProKey != null)
                {
                    if (objSystemsAdminProKey.GetValue(strProgramName) == null)
                        objSystemsAdminProKey.SetValue(strProgramName, "1", RegistryValueKind.String);
                }
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
            }
        }

        static DirectorySearcher funcCreateDSSearcher()
        {
            try
            {
                System.DirectoryServices.DirectorySearcher objDSSearcher = new DirectorySearcher();
                // [Comment] Get local domain context

                string rootDSE;

                System.DirectoryServices.DirectorySearcher objrootDSESearcher = new System.DirectoryServices.DirectorySearcher();
                rootDSE = objrootDSESearcher.SearchRoot.Path;
                //Console.WriteLine(rootDSE);

                // [Comment] Construct DirectorySearcher object using rootDSE string
                System.DirectoryServices.DirectoryEntry objrootDSEentry = new System.DirectoryServices.DirectoryEntry(rootDSE);
                objDSSearcher = new System.DirectoryServices.DirectorySearcher(objrootDSEentry);
                //Console.WriteLine(objDSSearcher.SearchRoot.Path);

                return objDSSearcher;
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                return null;
            }
        }

        static PrincipalContext funcCreatePrincipalContext()
        {
            PrincipalContext newctx = new PrincipalContext(ContextType.Machine);

            try
            {
                //Console.WriteLine("Entering funcCreatePrincipalContext");
                Domain objDomain = Domain.GetComputerDomain();
                string strDomain = objDomain.Name;
                DirectorySearcher tempDS = funcCreateDSSearcher();
                string strDomainRoot = tempDS.SearchRoot.Path.Substring(7);
                // [DebugLine] Console.WriteLine(strDomainRoot);
                // [DebugLine] Console.WriteLine(strDomainRoot);

                newctx = new PrincipalContext(ContextType.Domain,
                                    strDomain,
                                    strDomainRoot);

                // [DebugLine] Console.WriteLine(newctx.ConnectedServer);
                // [DebugLine] Console.WriteLine(newctx.Container);



                //if (strContextType == "Domain")
                //{

                //    PrincipalContext newctx = new PrincipalContext(ContextType.Domain,
                //                                    strDomain,
                //                                    strDomainRoot);
                //    return newctx;
                //}
                //else
                //{
                //    PrincipalContext newctx = new PrincipalContext(ContextType.Machine);
                //    return newctx;
                //}
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
            }

            if (newctx.ContextType == ContextType.Machine)
            {
                Exception newex = new Exception("The Active Directory context did not initialize properly.");
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, newex);
            }

            return newctx;
        }

        static void funcToEventLog(string strAppName, string strEventMsg, int intEventType)
        {
            try
            {
                string strLogName;

                strLogName = "Application";

                if (!EventLog.SourceExists(strAppName))
                    EventLog.CreateEventSource(strAppName, strLogName);

                //EventLog.WriteEntry(strAppName, strEventMsg);
                EventLog.WriteEntry(strAppName, strEventMsg, EventLogEntryType.Information, intEventType);
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
            }
        }

        static bool funcCheckForOU(string strOUPath)
        {
            try
            {
                string strDEPath = "";

                if (!strOUPath.Contains("LDAP://"))
                {
                    strDEPath = "LDAP://" + strOUPath;
                }
                else
                {
                    strDEPath = strOUPath;
                }

                if (DirectoryEntry.Exists(strDEPath))
                {
                    return true;
                }
                else
                {
                    return false;
                }

            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                return false;
            }
        }

        static bool funcCheckForFile(string strInputFileName)
        {
            try
            {
                if (System.IO.File.Exists(strInputFileName))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                return false;
            }
        }

        static void funcGetFuncCatchCode(string strFunctionName, Exception currentex)
        {
            string strCatchCode = "";

            Dictionary<string, string> dCatchTable = new Dictionary<string, string>();
            dCatchTable.Add("funcCheckForFile", "f0");
            dCatchTable.Add("funcCheckForOU", "f1");
            dCatchTable.Add("funcCloseOutputLog", "f2");
            dCatchTable.Add("funcCreateDSSearcher", "f3");
            dCatchTable.Add("funcCreatePrincipalContext", "f4");
            dCatchTable.Add("funcGetFuncCatchCode", "f5");
            dCatchTable.Add("funcLicenseActivation", "f6");
            dCatchTable.Add("funcLicenseCheck", "f7");
            dCatchTable.Add("funcOpenOutputLog", "f8");
            dCatchTable.Add("funcParseCmdArguments", "f9");
            dCatchTable.Add("funcParseConfigFile", "f10");
            dCatchTable.Add("funcPortableLicenseCheck", "f11");
            dCatchTable.Add("funcPrintParameterSyntax", "f12");
            dCatchTable.Add("funcPrintParameterWarning", "f13");
            dCatchTable.Add("funcProgramExecution", "f14");
            dCatchTable.Add("funcProgramRegistryTag", "f15");
            dCatchTable.Add("funcRecurse", "f16");
            dCatchTable.Add("funcToEventLog", "f17");
            dCatchTable.Add("funcWriteToErrorLog", "f18");
            dCatchTable.Add("funcWriteToOutputLog", "f19");

            if (dCatchTable.ContainsKey(strFunctionName))
            {
                strCatchCode = "err" + dCatchTable[strFunctionName] + ": ";
            }

            //[DebugLine] Console.WriteLine(strCatchCode + currentex.GetType().ToString());
            //[DebugLine] Console.WriteLine(strCatchCode + currentex.Message);

            funcWriteToErrorLog(strCatchCode + currentex.GetType().ToString());
            funcWriteToErrorLog(strCatchCode + currentex.Message);

        }

        static void funcWriteToErrorLog(string strErrorMessage)
        {
            try
            {
                FileStream newFileStream = new FileStream("Err-OWALogonExclusions.log", FileMode.Append, FileAccess.Write);
                TextWriter twErrorLog = new StreamWriter(newFileStream);

                DateTime dtNow = DateTime.Now;

                string dtFormat = "MMddyyyy HH:mm:ss";

                twErrorLog.WriteLine("{0} \t {1}", dtNow.ToString(dtFormat), strErrorMessage);

                twErrorLog.Close();
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
            }

        }

        static TextWriter funcOpenOutputLog()
        {
            try
            {
                DateTime dtNow = DateTime.Now;

                string dtFormat2 = "MMddyyyy"; // for log file directory creation

                string strPath = Directory.GetCurrentDirectory();

                if (!Directory.Exists(strPath + "\\Log"))
                {
                    Directory.CreateDirectory(strPath + "\\Log");
                    if (Directory.Exists(strPath + "\\Log"))
                    {
                        strPath = strPath + "\\Log";
                    }
                }
                else
                {
                    strPath = strPath + "\\Log";
                }

                string strLogFileName = strPath + "\\OWALogonExclusions" + dtNow.ToString(dtFormat2) + ".log";

                FileStream newFileStream = new FileStream(strLogFileName, FileMode.Append, FileAccess.Write);
                TextWriter twOuputLog = new StreamWriter(newFileStream);

                return twOuputLog;
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                return null;
            }

        }

        static void funcWriteToOutputLog(TextWriter twCurrent, string strOutputMessage)
        {
            try
            {
                DateTime dtNow = DateTime.Now;

                // string dtFormat = "MM/dd/yyyy";
                string dtFormat2 = "MM/dd/yyyy HH:mm";
                // string dtFormat3 = "MM/dd/yyyy HH:mm:ss";

                twCurrent.WriteLine("{0} \t {1}", dtNow.ToString(dtFormat2), strOutputMessage);
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
            }
        }

        static void funcCloseOutputLog(TextWriter twCurrent)
        {
            try
            {
                twCurrent.Close();
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
            }
        }

        static void funcRecurse(DirectoryInfo directory)
        {
            foreach (FileInfo fi in directory.GetFiles())
            {
                fi.Attributes = FileAttributes.Normal;
            }

            foreach (DirectoryInfo di in directory.GetDirectories())
            {
                di.Attributes = FileAttributes.Normal;
            }

            foreach (DirectoryInfo subdir2 in directory.GetDirectories())
            {
                funcRecurse(subdir2);
            }

        }

        static void funcProgramExecution(CMDArguments objCMDArguments2)
        {
            try
            {
                if (funcCheckForFile("configOWALogonExclusions.txt"))
                {
                    OWALogonParams newParams = funcParseConfigFile(objCMDArguments2);

                    funcToEventLog("OWALogonExclusions", "OWALogonExclusions started", 100);

                    funcProgramRegistryTag("OWALogonExclusions");

                    TextWriter twCurrent = funcOpenOutputLog();
                    string strOutputMsg = "";

                    strOutputMsg = "--------OWALogonExclusions started";
                    funcWriteToOutputLog(twCurrent, strOutputMsg);

                    PrincipalContext ctxDomain = funcCreatePrincipalContext();

                    Domain dmCurrent = Domain.GetCurrentDomain();
                    PrincipalContext ctxExclusionGroupLocation = new PrincipalContext(ContextType.Domain, dmCurrent.Name, newParams.strExclusionGroupLocation);
                    GroupPrincipal grpOWAExclusions = GroupPrincipal.FindByIdentity(ctxExclusionGroupLocation, IdentityType.SamAccountName, "OWALogonExclusions");

                    bool bRecreateGroup = false;

                    if (grpOWAExclusions != null)
                    {
                        DirectoryEntry grpDE = (DirectoryEntry)grpOWAExclusions.GetUnderlyingObject();
                        string strGrpCreated = funcGetAccountCreationDate(grpDE);
                        DateTime dtGrpCreated = Convert.ToDateTime(strGrpCreated);
                        if (dtGrpCreated < DateTime.Today.AddDays(-14))
                        {
                            grpDE.Close();
                            grpOWAExclusions.Delete();
                            bRecreateGroup = true;
                        }
                    }

                    if (grpOWAExclusions == null | bRecreateGroup)
                    {
                        grpOWAExclusions = new GroupPrincipal(ctxExclusionGroupLocation);
                        grpOWAExclusions.Name = "OWALogonExclusions";
                        grpOWAExclusions.SamAccountName = "OWALogonExclusions";
                        grpOWAExclusions.Description = "SystemsAdminPro Exclusions";
                        grpOWAExclusions.Save();
                    }

                    string[] strFiles = Directory.GetFiles(newParams.strOWALogFileLocation);

                    //[DebugLine] Console.WriteLine(strDirectories.Count<string>().ToString());

                    List<string> lstOWALogins = new List<string>();

                    string strRegPattern1 = "GET /\\w*/\\w*/Inbox/.*200 0 0";
                    string strRegPattern2 = "\\w*/Inbox/";

                    Regex regxOWALogin = new Regex(strRegPattern1);

                    foreach (string strFileName in strFiles)
                    {
                        DateTime dtFileCreation = File.GetCreationTime(strFileName);

                        if (dtFileCreation < DateTime.Today.AddHours(-12) & dtFileCreation > DateTime.Today.AddDays(-14))
                        {
                            //[DebugLine] Console.WriteLine(strFileName + " " + dtFileCreation.ToLocalTime().ToString("MMddyyyy"));

                            TextReader trLogFile = new StreamReader(strFileName);

                            using (trLogFile)
                            {
                                string strNewLine = "";

                                while ((strNewLine = trLogFile.ReadLine()) != null)
                                {
                                    if (regxOWALogin.IsMatch(strNewLine))
                                    {
                                        Match match = Regex.Match(strNewLine, strRegPattern2);
                                        //[DebugLine] Console.WriteLine("{0} \t {1}", match.Value, strFileName);
                                        string strLogin = match.Value.Substring(0, match.Value.IndexOf('/'));
                                        //[DebugLine] Console.WriteLine(strLogin);
                                        if (!lstOWALogins.Contains(strLogin))
                                        {
                                            lstOWALogins.Add(strLogin);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    //[DebugLine] Console.WriteLine();

                    funcToEventLog("OWALogonExclusions", "Number of OWA logons found: " + lstOWALogins.Count.ToString(), 1001);

                    foreach (string strUser in lstOWALogins)
                    {
                        UserPrincipal upTemp = UserPrincipal.FindByIdentity(ctxDomain, IdentityType.SamAccountName, strUser);

                        if (upTemp != null & upTemp.Enabled == true)
                        {
                            if (!funcCheckLoginRange(upTemp))
                            {
                                //[DebugLine] Console.WriteLine(upTemp.Name);
                                strOutputMsg = "OWA login found for: " + upTemp.Name;
                                funcWriteToOutputLog(twCurrent, strOutputMsg);

                                if (!upTemp.IsMemberOf(grpOWAExclusions))
                                {
                                    grpOWAExclusions.Members.Add(upTemp);
                                    grpOWAExclusions.Save();
                                    strOutputMsg = "Added to group " + grpOWAExclusions.Name + ": " + upTemp.Name;
                                    funcWriteToOutputLog(twCurrent, strOutputMsg);
                                }
                                else
                                {
                                    strOutputMsg = upTemp.Name + " is a member of the " + grpOWAExclusions.Name + " group";
                                    funcWriteToOutputLog(twCurrent, strOutputMsg);
                                }
                            }
                        }
                    }

                    strOutputMsg = "--------OWALogonExclusions stopped";
                    funcWriteToOutputLog(twCurrent, strOutputMsg);

                    funcCloseOutputLog(twCurrent);

                    funcToEventLog("OWALogonExclusions", "OWALogonExclusions stopped", 101);
                }
                else
                {
                    Console.WriteLine("configOWALogonExclusions.txt is required and could not be found.");
                }
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
            }
        }

        static string funcGetLastLogonTimestamp(DirectoryEntry tmpDE)
        {
            try
            {
                string strTimestamp = String.Empty;

                if (tmpDE.Properties.Contains("lastLogonTimestamp"))
                {
                    //[DebugLine] Console.WriteLine(u.Name + " has lastLogonTimestamp attribute");
                    IADsLargeInteger lintLogonTimestamp = (IADsLargeInteger)tmpDE.Properties["lastLogonTimestamp"].Value;
                    if (lintLogonTimestamp != null)
                    {
                        DateTime dtLastLogonTimestamp = funcGetDateTimeFromLargeInteger(lintLogonTimestamp);
                        if (dtLastLogonTimestamp != null)
                        {
                            strTimestamp = dtLastLogonTimestamp.ToLocalTime().ToString();
                        }
                        else
                        {
                            strTimestamp = "(null)";
                        }
                    }
                }

                return strTimestamp;
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                return String.Empty;
            }
        }

        static string funcGetAccountCreationDate(DirectoryEntry tmpDE)
        {
            try
            {
                string strCreationDate = String.Empty;

                if (tmpDE.Properties.Contains("whenCreated"))
                {
                    strCreationDate = (string)tmpDE.Properties["whenCreated"].Value.ToString();
                }

                return strCreationDate;
            }
            catch (Exception ex)
            {
                MethodBase mb1 = MethodBase.GetCurrentMethod();
                funcGetFuncCatchCode(mb1.Name, ex);
                return String.Empty;
            }
        }

        static DateTime funcGetDateTimeFromLargeInteger(IADsLargeInteger largeIntValue)
        {
            //
            // Convert large integer to int64 value
            //
            long int64Value = (long)((uint)largeIntValue.LowPart +
                     (((long)largeIntValue.HighPart) << 32));

            //
            // Return the DateTime in utc
            //
            // return DateTime.FromFileTimeUtc(int64Value);


            // return in Localtime
            return DateTime.FromFileTime(int64Value);
        }

        static bool funcCheckLoginRange(UserPrincipal upTemp)
        {
            try
            {
                string strlastLogonTimestamp = String.Empty;
                DirectoryEntry tmpDE = (DirectoryEntry)upTemp.GetUnderlyingObject();
                strlastLogonTimestamp = funcGetLastLogonTimestamp(tmpDE);
                tmpDE.Close();
                DateTime dtLogon = Convert.ToDateTime(strlastLogonTimestamp);
                if (dtLogon < DateTime.Today.AddDays(-14))
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    funcPrintParameterWarning();
                }
                else
                {
                    if (args[0] == "-?")
                    {
                        funcPrintParameterSyntax();
                    }
                    else
                    {
                        string[] arrArgs = args;
                        CMDArguments objArgumentsProcessed = funcParseCmdArguments(arrArgs);

                        if (objArgumentsProcessed.bParseCmdArguments)
                        {
                            funcProgramExecution(objArgumentsProcessed);
                        }
                        else
                        {
                            funcPrintParameterWarning();
                        } // check objArgumentsProcessed.bParseCmdArguments
                    } // check args[0] = "-?"
                } // check args.Length == 0
            }
            catch (Exception ex)
            {
                Console.WriteLine("errm0: {0}", ex.Message);
            }
        }
    }
}

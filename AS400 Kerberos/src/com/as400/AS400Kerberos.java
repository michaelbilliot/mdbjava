/*
 * Copyright (C) 2016 Michael Billiot <mdbilliot@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package com.as400;

import com.ibm.as400.access.AS400;
import com.sun.security.auth.callback.TextCallbackHandler;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.security.PrivilegedAction;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;

/**
 *
 * @author Michael Billiot <mdbilliot@gmail.com>
 */
public class AS400Kerberos {
  private AS400 as400;


  public AS400 getAS400() {
    return as400;
  }
  
  
  public void connect(String systemName) {
    File configuration = null;
        try {
            // create tmp file in which is the config to 'Krb5LoginModule'
            String fileName = System.getProperty("java.io.tmpdir") + "loginConf1";
            BufferedWriter out = new BufferedWriter(new FileWriter(fileName));
            out.write("SignedOnUserLoginContext {");
            out.newLine();
            out.write("com.sun.security.auth.module.Krb5LoginModule required useTicketCache=true doNotPrompt=true;");
            out.newLine();
            out.write("};");
            out.newLine();
            out.close();
            configuration = new File(fileName);
        } catch (Exception e) {
          }
    System.setProperty("java.security.auth.login.config", configuration.getAbsolutePath()); 
    LoginContext lc;
    try {
      lc = new LoginContext("SignedOnUserLoginContext", new TextCallbackHandler());
      lc.login();
      Subject.doAs(lc.getSubject(), (PrivilegedAction) () -> {
        try {
          as400 = new AS400(systemName);
          GSSManager gssManager = GSSManager.getInstance();
          GSSCredential cred = gssManager.createCredential(GSSCredential.INITIATE_ONLY);
          as400.setGSSOption(AS400.GSS_OPTION_MANDATORY);
          as400.setGuiAvailable(false);
          as400.setGSSCredential(cred);
          as400.connectService(AS400.SIGNON);
        } catch (Exception e) {
        }
        return as400;
      });
      
    } catch(Exception e) {
      e.printStackTrace();
    }
    
  }
  
  public void disconnect() {
    as400.disconnectAllServices();
  }
  
  public void testConnection() {
    try {
      
      System.out.println(as400.getSystemName());
      System.out.println(as400.getVersion() + "." + as400.getRelease());
      System.out.println(as400.getUserId());
    } catch(Exception e) {
      e.printStackTrace();
    }
    
  }

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) {
    AS400Kerberos system = new AS400Kerberos();
    system.connect(args[0]);
    system.testConnection();
    system.disconnect();
  }
  
}

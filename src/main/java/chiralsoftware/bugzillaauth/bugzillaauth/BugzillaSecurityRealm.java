package chiralsoftware.bugzillaauth.bugzillaauth;

import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.UncategorizedSQLException;

/**
 *
 * @author hh
 */
public class BugzillaSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    private static final Logger LOG = Logger.getLogger(BugzillaSecurityRealm.class.getName());
    
    public final String connectionUrl;
    public final String username;
    public final String password;
    public final String dbDriverName;

    @Override
    public String toString() {
        return "BugzillaSecurityRealm{" + "connectionUrl=" + connectionUrl + ", "
                + "username=" + username + ", dbDriverName=" + dbDriverName + '}';
    }
    
    @DataBoundConstructor 
    public BugzillaSecurityRealm(String connectionUrl, String username, String password, String dbDriverName) 
            throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        this.connectionUrl = connectionUrl;
        this.username = username;
        this.password = password;
        this.dbDriverName = dbDriverName;
        LOG.info("BugzillaSecurityRealm configured: " + this);
    }
    
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        /** Return the help file, which is displayed on Configure Global Security
         * when the user clicks the help icon.
         * This file is a static resource relative to the webapp directory
         * @return 
         */
        @Override
        public String getHelpFile() {
            return "/plugin/bugzillaauth/help/overview.html";
        }

        /**
         * In order to load the persisted global configuration, you have to 
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            load();
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types 
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Use Bugzilla login database";
        }
    }
    
    private boolean driverLoaded = false;
    private void loadDriver() throws DataAccessException {
        if(driverLoaded) return;
        try {
            Class.forName(dbDriverName).newInstance();
            driverLoaded = true;
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException ex) {
            LOG.log(Level.SEVERE, "Could not load db driver class : " + dbDriverName, ex);
            throw new DataAccessResourceFailureException("Could not load db driver class: " + dbDriverName, ex);
        }
    }
    
    @Override
    protected UserDetails authenticate(String webUsername, String webPassword) throws AuthenticationException {
        if(webUsername == null || webUsername.isEmpty()) throw new BugzillaAuthenticationException("Username was null or empty");
        if(webPassword == null || webPassword.isEmpty()) throw new BugzillaAuthenticationException("Password was null or empty");
        loadDriver();
        Connection connection = null;
        try {
            // This is not great but here goes
            
            final Properties connectionProperties = new Properties();
            connectionProperties.put("user", username);
            connectionProperties.put("password", password);
            connection = DriverManager.getConnection(connectionUrl, connectionProperties);
            // we really should store the prepared statement
            final PreparedStatement preparedStatement = 
                    connection.prepareStatement("select * from profiles where login_name = ?");
            preparedStatement.setString(1, webUsername);
            final ResultSet rs = preparedStatement.executeQuery();
            if(! rs.next()) 
                throw new BugzillaAuthenticationException("User not found");
            final String saltyPassword = rs.getString("cryptpassword");
            // this has a format like:
            // salt,encryptedpw{SHA-256}
//            LOG.fine("Salty password string for user:" + webUsername + ": " + saltyPassword);
            final String[] sa = saltyPassword.split(",");
            final String savedPassword = sa[1].substring(0,sa[1].indexOf('{'));
            final String salt = sa[0];
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(webPassword.getBytes());
            md.update(salt.getBytes());
            final String hashResult = encodeBase64String(md.digest());
//            LOG.info("The hash result is: " + hashResult + " and I need to compare it to :" + savedPassword);
            if(! hashResult.startsWith(savedPassword)) 
                throw new BugzillaAuthenticationException("Password was not valid");
            // cool, we have a successful user and must return a UserDetails object
            final Set<GrantedAuthority> groups = new HashSet<>();
            // ideally we should map Bugzilla's authorities to Jenkins roles
            groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
            final UserDetails userDetails = new BugzillaUserDetail(webUsername, webPassword, 
                    true, true, true, true, groups.toArray(new GrantedAuthority[groups.size()]));
            return userDetails;
        } catch(SQLException ex) {
            LOG.log(Level.SEVERE, "SQLException connecting to URL: " + connectionUrl, ex);
            throw new BugzillaAuthenticationException("SQLException connecting to URL: " + connectionUrl, ex);
        } catch(NoSuchAlgorithmException ex) {
            LOG.log(Level.SEVERE, "could not use the requested hash alg", ex);
            throw new BugzillaAuthenticationException("could not use the requested hash alg", ex);
        } finally {
            if(connection != null)
                try {
                    connection.close();
            } catch (SQLException ex) {
                LOG.log(Level.SEVERE,"Could not close connection",ex);
            }
        }
        
    }

    @Override
    public UserDetails loadUserByUsername(String webUsername) throws UsernameNotFoundException, DataAccessException {
        if(webUsername == null || webUsername.isEmpty()) 
            throw new UsernameNotFoundException("User name was null or null");
         loadDriver();
       Connection connection = null;
        final String query = "select * from profiles where login_name = ?";
        try {
            // This is not great but here goes
            
            final Properties connectionProperties = new Properties();
            connectionProperties.put("user", username);
            connectionProperties.put("password", password);
            connection = DriverManager.getConnection(connectionUrl, connectionProperties);
            // we really should store the prepared statement
            final PreparedStatement preparedStatement = 
                    connection.prepareStatement(query);
            preparedStatement.setString(1, webUsername);
            final ResultSet rs = preparedStatement.executeQuery();
            if(! rs.next()) 
                throw new UsernameNotFoundException("User: " + webUsername + " not found");
            final Set<GrantedAuthority> groups = new HashSet<>();
            // ideally we should map Bugzilla's authorities to Jenkins roles
            groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
            final UserDetails userDetails = new BugzillaUserDetail(webUsername, rs.getString("cryptpassword"), 
                    true, true, true, true, groups.toArray(new GrantedAuthority[groups.size()]));
            return userDetails;        } catch(SQLException ex) {
            throw new UncategorizedSQLException("Caught SQL exception", query,ex);
        } finally {
            if(connection != null) try {
                connection.close();
            } catch (SQLException ex) {
                LOG.log(Level.SEVERE, "Caught exception while trying to close DB", ex);
            }
        }     
        
    }

    @Override
    public GroupDetails loadGroupByGroupname(String string) throws UsernameNotFoundException, DataAccessException {
        LOG.warning("NON-SUPPORTED OPERATION.  Here are thet groups: " + string);
        throw new UsernameNotFoundException("Non-supported operation");
    }
    
}

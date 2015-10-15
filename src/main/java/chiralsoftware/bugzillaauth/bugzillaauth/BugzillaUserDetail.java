package chiralsoftware.bugzillaauth.bugzillaauth;

import java.util.logging.Logger;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

/**
 *
 */
public final class BugzillaUserDetail implements UserDetails {

    public BugzillaUserDetail(String username, String password, boolean enabled,
            boolean accountNonExpired, boolean credentialsNonExpired,
            boolean accountNonLocked, GrantedAuthority[] authorities)
            throws IllegalArgumentException {
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.accountNotExpired = accountNonExpired;
        this.credentialsNotExpired = credentialsNonExpired;
        this.accountNotLocked = accountNonLocked;
        this.authorities = authorities;
    }

    @Override
    public String toString() {
        return "BugzillaUserDetail{" + "authorities=" + authorities + ", username=" + username + ", "
                + "accountNotExpired=" + accountNotExpired + ", accountNotLocked=" + accountNotLocked + ", "
                + "credentialsNotExpired=" + credentialsNotExpired + ", enabled=" + enabled + '}';
    }
    
    @Override
    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return accountNotExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNotLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNotExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    private final GrantedAuthority[] authorities;
    private final String password;
    private final String username;
    private final boolean accountNotExpired;
    private final boolean accountNotLocked;
    private final boolean credentialsNotExpired;
    private final boolean enabled;
}

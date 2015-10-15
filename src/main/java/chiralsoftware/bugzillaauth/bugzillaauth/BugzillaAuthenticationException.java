package chiralsoftware.bugzillaauth.bugzillaauth;

import org.acegisecurity.AuthenticationException;

/**
 * Signals a failed authentication attempt to the external database.
 *
 */
public final class BugzillaAuthenticationException extends AuthenticationException {

    public BugzillaAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    public BugzillaAuthenticationException(String msg) {
        super(msg);
    }
}

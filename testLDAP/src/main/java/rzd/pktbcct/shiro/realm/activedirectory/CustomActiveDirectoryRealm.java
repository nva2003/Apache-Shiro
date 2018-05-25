package rzd.pktbcct.shiro.realm.activedirectory;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.activedirectory.ActiveDirectoryRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * User: VNikishin
 * Date: 24.05.18
 * Time: 14:28
 */
public class CustomActiveDirectoryRealm extends ActiveDirectoryRealm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final Logger log = LoggerFactory.getLogger(CustomActiveDirectoryRealm.class);
    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    //SHIRO-115 - prevent potential code injection:
//            String searchFilter = "(&(objectClass=*)(sAMAccountName={0}))";
//        String searchFilter = "(&(objectClass=*)(userPrincipalName={0}))";

    protected String searchFilter = "(&(objectClass=*)(sAMAccountName={0}))";
    protected String groupSearchFilter = "(&(objectClass=*)(sAMAccountName={0}))";

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }

    /**
     * Builds an {@link org.apache.shiro.authz.AuthorizationInfo} object by querying the active directory LDAP context for the
     * groups that a user is a member of.  The groups are then translated to role names by using the
     * configured {@link #groupRolesMap}.
     * <p/>
     * This implementation expects the <tt>principal</tt> argument to be a String username.
     * <p/>
     * Subclasses can override this method to determine authorization data (roles, permissions, etc) in a more
     * complex way.  Note that this default implementation does not support permissions, only roles.
     *
     * @param principals         the principal of the Subject whose account is being retrieved.
     * @param ldapContextFactory the factory used to create LDAP connections.
     * @return the AuthorizationInfo for the given Subject principal.
     * @throws NamingException if an error occurs when searching the LDAP server.
     */
    @Override
    protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals, LdapContextFactory ldapContextFactory) throws NamingException {

        String username = (String) getAvailablePrincipal(principals);

        // Perform context search
        LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();

        Set<String> roleNames;

        try {
            roleNames = getRoleNamesForUser(username, ldapContext);
        } finally {
            LdapUtils.closeContext(ldapContext);
        }

        return buildAuthorizationInfo(roleNames);
    }

    private Set<String> getRoleNamesForUser(String username, LdapContext ldapContext) throws NamingException {
        Set<String> roleNames;
        roleNames = new LinkedHashSet<String>();



        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//        String[] attrIDs = {"memberOf"};
//        searchCtls.setReturningAttributes(attrIDs);

        String userPrincipalNameInSpase = null;
        String userPrincipalName = username;
        //deprecated
        if (principalSuffix != null) {
            userPrincipalName += principalSuffix;
        }

        Object[] searchArguments = new Object[]{userPrincipalName};

        NamingEnumeration answer = ldapContext.search(searchBase, groupSearchFilter, searchArguments, searchCtls);

        while (answer.hasMoreElements()) {
            SearchResult sr = (SearchResult) answer.next();

            if (log.isDebugEnabled()) {
                log.debug("Retrieving group names for user [" + sr.getName() + "]");
            }

            Attributes attrs = sr.getAttributes();

            if (attrs != null) {



                NamingEnumeration ae = attrs.getAll();
                while (ae.hasMore()) {
                    Attribute attr = (Attribute) ae.next();

                    if (attr.getID().equals("memberOf")) {

                        Collection<String> groupNames = LdapUtils.getAllAttributeValues(attr);

                        if (log.isDebugEnabled()) {
                            log.debug("Groups found for user [" + username + "]: " + groupNames);
                        }

                        Collection<String> rolesForGroups = getRoleNamesForGroups(groupNames);
                        roleNames.addAll(rolesForGroups);
                    }


                }
            }

            userPrincipalNameInSpase = sr.getNameInNamespace();

        }

        if (userPrincipalNameInSpase != null) {
            roleNames.addAll(getRoleNamesFromGroups(userPrincipalNameInSpase, ldapContext));
        }

        return roleNames;
    }




    private Collection<String>  getRoleNamesFromGroups(String distinguishedName, LdapContext ldapContext) throws NamingException {

        Set<String> roleNames = new HashSet<String>();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);


        String[] attrIDs = {"cn","sAMAccountName","name"};
        searchCtls.setReturningAttributes(attrIDs);
        String searchFilter = "(&(objectclass=group)(member="+distinguishedName+"))";


        NamingEnumeration<?> answer = ldapContext.search(searchBase, searchFilter , searchCtls);


        while (answer.hasMore()) {
            SearchResult rslt = (SearchResult) answer.next();
            Attributes attrs = rslt.getAttributes();
            String group = getAttributeValue("name",attrs);
            roleNames.add(group);
        }
        return roleNames;
    }

    /**
     * Return a String representing the value of the specified attribute.
     *
     * @param attrId Attribute name
     * @param attrs Attributes containing the required value
     * @return the attribute value
     * @exception NamingException if a directory server error occurs
     */
    private String getAttributeValue(String attrId, Attributes attrs)
            throws NamingException {

        if (attrId == null || attrs == null)
            return null;

        Attribute attr = attrs.get(attrId);
        if (attr == null)
            return null;
        Object value = attr.get();
        if (value == null)
            return null;
        String valueString = null;
        if (value instanceof byte[])
            valueString = new String((byte[]) value);
        else
            valueString = value.toString();

        return valueString;
    }

}

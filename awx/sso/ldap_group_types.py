# Copyright (c) 2018 Ansible by Red Hat
# All Rights Reserved.

# Python
import ldap

# Django
from django.utils.encoding import force_str

# 3rd party
from django_auth_ldap.config import LDAPGroupType
from django_auth_ldap.config import NestedActiveDirectoryGroupType


class PosixUIDGroupType(LDAPGroupType):

    def __init__(self, name_attr='cn', ldap_group_user_attr='uid'):
        self.ldap_group_user_attr = ldap_group_user_attr
        super(PosixUIDGroupType, self).__init__(name_attr)

    """
    An LDAPGroupType subclass that handles non-standard DS.
    """
    def user_groups(self, ldap_user, group_search):
        """
        Searches for any group that is either the user's primary or contains the
        user as a member.
        """
        groups = []

        try:
            user_uid = ldap_user.attrs[self.ldap_group_user_attr][0]

            if 'gidNumber' in ldap_user.attrs:
                user_gid = ldap_user.attrs['gidNumber'][0]
                filterstr = u'(|(gidNumber=%s)(memberUid=%s))' % (
                    self.ldap.filter.escape_filter_chars(user_gid),
                    self.ldap.filter.escape_filter_chars(user_uid)
                )
            else:
                filterstr = u'(memberUid=%s)' % (
                    self.ldap.filter.escape_filter_chars(user_uid),
                )

            search = group_search.search_with_additional_term_string(filterstr)
            search.attrlist = [str(self.name_attr)]
            groups = search.execute(ldap_user.connection)
        except (KeyError, IndexError):
            pass

        return groups

    def is_member(self, ldap_user, group_dn):
        """
        Returns True if the group is the user's primary group or if the user is
        listed in the group's memberUid attribute.
        """
        is_member = False
        try:
            user_uid = ldap_user.attrs[self.ldap_group_user_attr][0]

            try:
                is_member = ldap_user.connection.compare_s(force_str(group_dn), 'memberUid', force_str(user_uid))
            except (ldap.UNDEFINED_TYPE, ldap.NO_SUCH_ATTRIBUTE):
                is_member = False

            if not is_member:
                try:
                    user_gid = ldap_user.attrs['gidNumber'][0]
                    is_member = ldap_user.connection.compare_s(force_str(group_dn), 'gidNumber', force_str(user_gid))
                except (ldap.UNDEFINED_TYPE, ldap.NO_SUCH_ATTRIBUTE):
                    is_member = False
        except (KeyError, IndexError):
            is_member = False

        return is_member

class ReferralADGroupType(NestedActiveDirectoryGroupType):
    def user_groups(self, ldap_user, group_search):
        self.ldap_user = ldap_user
        ret = super(ReferralADGroupType, self).user_groups(ldap_user, group_search)
        #logger.info("User groups are %s", ret)
        return ret

    def find_groups_with_any_member(self, member_dn_set, group_search, connection):
        terms = [
            "({}={})".format(self.member_attr, self.ldap.filter.escape_filter_chars(dn))
            for dn in member_dn_set
        ]

        filterstr = "(|{})".format("".join(terms))
        if hasattr(group_search, "searches"):
            searches = [s.search_with_additional_term_string(filterstr) for s in group_search.searches]
        else:
            searches = [group_search.search_with_additional_term_string(filterstr)]
        
        ret = []
        for search in searches:
            if self.ldap_user.backend.is_referral(search.base_dn):
                search_conn = self.ldap_user.backend.connection_to(search.base_dn)    
            else:
                search_conn = connection
            s_res = search.execute(search_conn)
            if s_res:
                ret.extend(s_res)
        return ret
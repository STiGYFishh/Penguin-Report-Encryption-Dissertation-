from confusable_homoglyphs import confusables
from django.core.exceptions import ValidationError
from django.utils import six
from django.utils.translation import ugettext_lazy as _
import json
import os
import re

# Credit to James Bennett (ubernostrum) for the majority of this validator file from the django-registration project.
# https://github.com/ubernostrum/django-registration

CONFUSABLE = _(u"This name cannot be registered. Please choose a different name.")
CONFUSABLE_EMAIL = _(u"This email address cannot be registered. Please supply a different email address.")
DUPLICATE_EMAIL = _(u"This email address is already in use. Please supply a different email address.")
FREE_EMAIL = _(u"Registration using free email addresses is prohibited. Please supply a different email address.")
RESERVED_NAME = _(u"This name is reserved and cannot be registered.")
TOS_REQUIRED = _(u"You must agree to the terms to register")


# Below we construct a large but non-exhaustive list of names which
# users probably should not be able to register with, due to various
# risks:
#
# * For a site which creates email addresses from username, important
#   common addresses must be reserved.
#
# * For a site which uses the username to generate a URL to the user's
#   profile, common well-known filenames must be reserved.
#
# etc., etc.
#
# Credit for basic idea and most of the list to Geoffrey Thomas's blog
# post about names to reserve:
# https://ldpreload.com/blog/names-to-reserve

SPECIAL_HOSTNAMES = [
    'autoconfig',     # Thunderbird autoconfig
    'autodiscover',   # MS Outlook/Exchange autoconfig
    'broadcasthost',  # Network broadcast hostname
    'isatap',         # IPv6 tunnel autodiscovery
    'localdomain',    # Loopback
    'localhost',      # Loopback
    'wpad',           # Proxy autodiscovery
]


PROTOCOL_HOSTNAMES = [
    'ftp',
    'imap',
    'mail',
    'news',
    'pop',
    'pop3',
    'smtp',
    'usenet',
    'uucp',
    'webmail',
    'www',
]


CA_ADDRESSES = [
    'admin',
    'administrator',
    'hostmaster',
    'info',
    'is',
    'it',
    'mis',
    'postmaster',
    'root',
    'ssladmin',
    'ssladministrator',
    'sslwebmaster',
    'sysadmin',
    'webmaster',
]


RFC_2142 = [
    'abuse',
    'marketing',
    'noc',
    'sales',
    'security',
    'support',
]


NOREPLY_ADDRESSES = [
    'mailer-daemon',
    'nobody',
    'noreply',
    'no-reply',
]


SENSITIVE_FILENAMES = [
    'clientaccesspolicy.xml', 
    'crossdomain.xml',
    'favicon.ico',
    'humans.txt',
    'keybase.txt',
    'robots.txt',
    '.htaccess',
    '.htpasswd',
]


OTHER_SENSITIVE_NAMES = [
    'account',
    'accounts',
    'blog',
    'buy',
    'clients',
    'contact',
    'contactus',
    'contact-us',
    'copyright',
    'dashboard',
    'doc',
    'docs',
    'download',
    'downloads',
    'enquiry',
    'faq',
    'help',
    'inquiry',
    'license',
    'login',
    'logout',
    'me',
    'myaccount',
    'payments',
    'plans',
    'portfolio',
    'preferences',
    'pricing',
    'privacy',
    'profile',
    'register'
    'secure',
    'settings',
    'signin',
    'signup',
    'ssl',
    'status',
    'subscribe',
    'terms',
    'tos',
    'user',
    'users'
    'weblog',
    'work',
]


DEFAULT_RESERVED_NAMES = (
    SPECIAL_HOSTNAMES + PROTOCOL_HOSTNAMES + CA_ADDRESSES + RFC_2142 +
    NOREPLY_ADDRESSES + SENSITIVE_FILENAMES + OTHER_SENSITIVE_NAMES
)


class ReservedNameValidator(object):
    """
    Validator which disallows many reserved names as form field
    values.

    """
    def __init__(self, reserved_names=DEFAULT_RESERVED_NAMES):
        self.reserved_names = reserved_names

        module_dir = os.path.dirname(__file__)  # get current directory
        file_path = os.path.join(module_dir, 'bad_words.txt')
        try:
            with open(file_path,'r') as f:
                self.bad_words = json.load(f)
        except OSError:
            self.bad_words = []

    def __call__(self, value):
        # GH issue 82: this validator only makes sense when the
        # username field is a string type.
        if not isinstance(value, six.text_type):
            return
        if any([value.lower() in self.reserved_names,value.startswith('.well-known'),value.lower() in self.bad_words]):
            raise ValidationError(RESERVED_NAME, code='invalid')


def validate_confusables(value):
    """
    Validator which disallows 'dangerous' usernames likely to
    represent homograph attacks.

    A username is 'dangerous' if it is mixed-script (as defined by
    Unicode 'Script' property) and contains one or more characters
    appearing in the Unicode Visually Confusable Characters file.

    """
    if not isinstance(value, six.text_type):
        return
    if confusables.is_dangerous(value):
        raise ValidationError(CONFUSABLE, code='invalid')


def validate_confusables_email(value):
    """
    Validator which disallows 'dangerous' email addresses likely to
    represent homograph attacks.

    An email address is 'dangerous' if either the local-part or the
    domain, considered on their own, are mixed-script and contain one
    or more characters appearing in the Unicode Visually Confusable
    Characters file.

    """
    if '@' not in value:
        return
    local_part, domain = value.split('@')
    if confusables.is_dangerous(local_part) or \
       confusables.is_dangerous(domain):
        raise ValidationError(CONFUSABLE_EMAIL, code='invalid')


def string_validate(value):
    if not re.match(r'^[a-zA-Z0-9-_\s]+$', value):
        raise ValidationError('Only alphanumeric plus the characters \'-\' and \'_\' allowed.')
    validate_confusables(value)
    ReservedNameValidator(value)

    return value

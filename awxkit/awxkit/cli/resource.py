import yaml
import json
import os

from awxkit import api, config
from awxkit.exceptions import ImportExportError
from awxkit.utils import to_str
from awxkit.api.pages import Page
from awxkit.api.pages.api import EXPORTABLE_RESOURCES
from awxkit.cli.format import FORMATTERS, format_response, add_authentication_arguments
from awxkit.cli.utils import CustomRegistryMeta, cprint


CONTROL_RESOURCES = ['ping', 'config', 'me', 'metrics']

DEPRECATED_RESOURCES = {
    'ad_hoc_commands': 'ad_hoc',
    'applications': 'application',
    'credentials': 'credential',
    'credential_types': 'credential_type',
    'groups': 'group',
    'hosts': 'host',
    'instances': 'instance',
    'instance_groups': 'instance_group',
    'inventory': 'inventories',
    'inventory_scripts': 'inventory_script',
    'inventory_sources': 'inventory_source',
    'inventory_updates': 'inventory_update',
    'jobs': 'job',
    'job_templates': 'job_template',
    'labels': 'label',
    'workflow_job_template_nodes': 'node',
    'notification_templates': 'notification_template',
    'organizations': 'organization',
    'projects': 'project',
    'project_updates': 'project_update',
    'roles': 'role',
    'schedules': 'schedule',
    'settings': 'setting',
    'teams': 'team',
    'workflow_job_templates': 'workflow',
    'workflow_jobs': 'workflow_job',
    'users': 'user'
}
DEPRECATED_RESOURCES_REVERSE = dict(
    (v, k) for k, v in DEPRECATED_RESOURCES.items()
)


class CustomCommand(metaclass=CustomRegistryMeta):
    """Base class for implementing custom commands.

    Custom commands represent static code which should run - they are
    responsible for returning and formatting their own output (which may or may
    not be JSON/YAML).
    """

    help_text = ''

    @property
    def name(self):
        raise NotImplementedError()

    def handle(self, client, parser):
        """To be implemented by subclasses.
        Should return a dictionary that is JSON serializable
        """
        raise NotImplementedError()


class Login(CustomCommand):
    name = 'login'
    help_text = 'authenticate and retrieve an OAuth2 token'

    def print_help(self, parser):
        add_authentication_arguments(parser, os.environ)
        parser.print_help()

    def handle(self, client, parser):
        auth = parser.add_argument_group('OAuth2.0 Options')
        auth.add_argument('--description', help='description of the generated OAuth2.0 token', metavar='TEXT')
        auth.add_argument('--conf.client_id', metavar='TEXT')
        auth.add_argument('--conf.client_secret', metavar='TEXT')
        auth.add_argument(
            '--conf.scope', choices=['read', 'write'], default='write'
        )
        if client.help:
            self.print_help(parser)
            raise SystemExit()
        parsed = parser.parse_known_args()[0]
        kwargs = {
            'client_id': getattr(parsed, 'conf.client_id', None),
            'client_secret': getattr(parsed, 'conf.client_secret', None),
            'scope': getattr(parsed, 'conf.scope', None),
        }
        if getattr(parsed, 'description', None):
            kwargs['description'] = parsed.description
        try:
            token = api.Api().get_oauth2_token(**kwargs)
        except Exception as e:
            self.print_help(parser)
            cprint(
                'Error retrieving an OAuth2.0 token ({}).'.format(e.__class__),
                'red'
            )
        else:
            fmt = client.get_config('format')
            if fmt == 'human':
                print('export TOWER_OAUTH_TOKEN={}'.format(token))
            else:
                print(to_str(FORMATTERS[fmt]({'token': token}, '.')).strip())


class Config(CustomCommand):
    name = 'config'
    help_text = 'print current configuration values'

    def handle(self, client, parser):
        if client.help:
            parser.print_help()
            raise SystemExit()
        return {
            'base_url': config.base_url,
            'token': client.get_config('token'),
            'use_sessions': config.use_sessions,
            'credentials': config.credentials,
        }


class Import(CustomCommand):
    name = 'import'
    help_text = 'import resources into Tower'

    def handle(self, client, parser):
        if client.help:
            parser.print_help()
            raise SystemExit()

        format = getattr(client.args, 'conf.format')
        if format == 'json':
            data = json.load(client.stdin)
        elif format == 'yaml':
            data = yaml.safe_load(client.stdin)
        else:
            raise ImportExportError("Unsupported format for Import: " + format)

        client.authenticate()
        client.v2.import_assets(data)

        return {}


class Export(CustomCommand):
    name = 'export'
    help_text = 'export resources from Tower'

    def extend_parser(self, parser):
        resources = parser.add_argument_group('resources')

        for resource in EXPORTABLE_RESOURCES:
            # This parsing pattern will result in 3 different possible outcomes:
            # 1) the resource flag is not used at all, which will result in the attr being None
            # 2) the resource flag is used with no argument, which will result in the attr being ''
            # 3) the resource flag is used with an argument, and the attr will be that argument's value
            resources.add_argument('--{}'.format(resource), nargs='?', const='')

    def handle(self, client, parser):
        self.extend_parser(parser)

        if client.help:
            parser.print_help()
            raise SystemExit()

        parsed = parser.parse_known_args()[0]
        kwargs = {resource: getattr(parsed, resource, None) for resource in EXPORTABLE_RESOURCES}

        client.authenticate()
        return client.v2.export_assets(**kwargs)


def parse_resource(client, skip_deprecated=False):
    subparsers = client.parser.add_subparsers(
        dest='resource',
        metavar='resource',
    )

    # check if the user is running a custom command
    for command in CustomCommand.__subclasses__():
        client.subparsers[command.name] = subparsers.add_parser(
            command.name, help=command.help_text
        )

    if hasattr(client, 'v2'):
        for k in client.v2.json.keys():
            if k in ('dashboard',):
                # the Dashboard API is deprecated and not supported
                continue

            # argparse aliases are *only* supported in Python3 (not 2.7)
            kwargs = {}
            if not skip_deprecated:
                if k in DEPRECATED_RESOURCES:
                    kwargs['aliases'] = [DEPRECATED_RESOURCES[k]]

            client.subparsers[k] = subparsers.add_parser(
                k, help='', **kwargs
            )

    resource = client.parser.parse_known_args()[0].resource
    if resource in DEPRECATED_RESOURCES.values():
        client.argv[
            client.argv.index(resource)
        ] = DEPRECATED_RESOURCES_REVERSE[resource]
        resource = DEPRECATED_RESOURCES_REVERSE[resource]

    if resource in CustomCommand.registry:
        parser = client.subparsers[resource]
        command = CustomCommand.registry[resource]()
        response = command.handle(client, parser)
        if response:
            _filter = client.get_config('filter')
            if (
                resource == 'config' and
                client.get_config('format') == 'human'
            ):
                response = {
                    'count': len(response),
                    'results': [
                        {'key': k, 'value': v}
                        for k, v in response.items()
                    ]
                }
                _filter = 'key, value'
            try:
                connection = client.root.connection
            except AttributeError:
                connection = None
            formatted = format_response(
                Page.from_json(response, connection=connection),
                fmt=client.get_config('format'),
                filter=_filter
            )
            print(formatted)
        raise SystemExit()
    else:
        return resource


def is_control_resource(resource):
    # special root level resources that don't don't represent database
    # entities that follow the list/detail semantic
    return resource in CONTROL_RESOURCES

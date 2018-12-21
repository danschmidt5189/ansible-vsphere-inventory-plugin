from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils._text import to_text
from ansible.plugins.inventory import \
    BaseInventoryPlugin, Constructable, Cacheable
from collections import deque

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

HAS_SOCKS = True
try:
    import socket
    import socks
except ImportError:
    HAS_SOCKS = False

HAS_PYVMOMI = True
try:
    from pyVmomi import vim, vmodl, VmomiSupport
    from pyVim.connect import SmartConnection
except ImportError:
    HAS_PYVMOMI = False

DOCUMENTATION = """
    name: vsphere
    plugin_type: inventory
    short_description: vmware vsphere inventory source
    extends_documentation_fragment:
        - inventory_cache
        - constructed
    requirements:
        - pyVmomi
        - socks (if using a SOCKS5 proxy)
    description:
        - Get inventory from VMware vSphere.
        - Uses a <name>.vsphere.yml YAML configuration file.
    options:
        plugin:
            description: Token ensuring the config file is for this plugin.
            required: True
            choices: ['vsphere']
        hostname:
            description: vSphere host address
            default: vps.mysite.com
            env:
                - name: VSPHERE_HOSTNAME
            type: string
            version_added: 0.1
        username:
            description: vSphere username
            default: vps-user@mysite.com
            env:
                - name: VSPHERE_AUTH_USR
            type: string
            version_added: 0.1
        password:
            description: vSphere password
            env:
                - name: VSPHERE_AUTH_PSW
            type: string
            version_added: 0.1
        proxy_host:
            description: SOCKS5 proxy host. Useful for offsite access.
            env:
                - name: SOCKS5_PROXY_HOST
            type: string
            version_added: 0.1
        proxy_port:
            description: SOCKS5 proxy port. Useful for offsite access.
            default: 8124
            env:
                - name: SOCKS5_PROXY_PORT
            type: integer
            version_added: 0.1
        default_hostname:
            description: Expression used to derive default inventory_hostname.
            default: props['name'] + '---' + props['config.uuid']
            type: string
            version_added: 0.1
        hostvars:
            description: Mapping of hostvar expressions
            type: dictionary
            version_added: 0.1
        groups:
            description: List of grouping expressions
            type: list
            version_added: 0.1
        filters:
            description: List of expressions used to filter out hosts
            type: list
            version_added: 0.1
"""


EXAMPLES = """
# A typical configuration
plugin: vsphere

hostname: my-vcenter.my-site.com
username: my-vcenter-user
password: lookup('osxkeychain', 'lookups are allowed...')

hostvars:
  ansible_host: >
    props['guest.net']
    | map(attribute='ipAddress')
    | sum(start=[])
    | ipv4('public')
    | first
  inventory_hostname: props['guest.hostName']
  vsphere_config_template: props['config.template'] | bool
  vsphere_folder: props['folder']
  vsphere_guest_guestFamily: props['guest.guestFamily']

groups:
  - hostvars['vsphere_guest_guestFamily']
  - >
    hostvars['vsphere_folder'].split('/')
    | reject('in', ['vm', 'Colo', 'LIB', 'Dedicated Cluster VMs'])
    | list

filters:
  - not hostvars['vsphere_config_template']
  - hostvars['ansible_host'] | ipv4('public')
  - hostvars['vsphere_guest_guestFamily'] not in ['windowsGuest']
"""


class InventoryModule(BaseInventoryPlugin, Cacheable, Constructable):

    NAME = 'vsphere'  # Used internally by Ansible

    def parse(self, inventory, loader, path, cache=True):
        """Populate inventory with hosts and groups"""

        # Ensure self.loader, path, etc. are set and available to other methods
        super(InventoryModule, self).parse(
            inventory, loader, path, cache=cache)

        # Populates self._options
        self._read_config_data(path)

        # Cacheable inventory data
        inventory = {}

        # Because we fetch all available data from vSphere, use a shared cache
        # keyed on the user/host of the vCenter.
        cache_key = self.get_cache_key('%s@%s' % (
            self.get_option('username'), self.get_option('hostname')))

        # Try fetching from cache
        if cache and self.cache:
            try:
                inventory = self.cache.get(cache_key)
            except KeyError:
                pass

        # Refresh from vSphere if skipping cache
        if not inventory:
            inventory = self._extract_inventory(self._execute_search())

            # Update the cache
            if cache and self.cache:
                self.cache.set(cache_key, inventory)

        # Generator yielding hosts from the raw data
        for host in self._extract_hosts(inventory):
            self._add_host(host)

    def verify_file(self, path):
        """Return whether the given path is a config for this plugin"""

        if not super(InventoryModule, self).verify_file(path):
            raise AnsibleParserError("Config file unreadable.")

        if not path.endswith(('vsphere.yml', 'vsphere.yaml')):
            raise AnsibleParserError(
                "Config file doesn't match '*vsphere.ya?ml'")

        if not HAS_PYVMOMI:
            raise AnsibleParserError("The 'pyVmomi' Python package is missing "
                                     "and it is required. Please install it.")

        if not HAS_SOCKS:
            display.warning("The 'socks' Python package is required if using "
                            "tunnels. If you run into weird import errors, "
                            "check this out.")

        return True

    def _add_host(self, host):
        """Adds a single host to the inventory"""

        display.debug("Adding '%(name)s' with groups: %(groups)s" % host)

        self.inventory.add_host(host['name'], group=None)

        for k, v in host['hostvars'].iteritems():
            self.inventory.set_variable(host['name'], k, v)

        for group_name in host['groups']:
            self.inventory.add_group(group_name)
            self.inventory.add_child(group_name, host['name'])

    def _extract_hosts(self, inventory):
        """Yields hosts from cacheable dictionary of inventory data"""

        for uid, props in virtual_machines(inventory):
            host = self._new_host(props)

            display.debug('Processing host: %(name)s' % host)
            self._apply_hostvar_patterns(host)
            self._apply_groups_patterns(host)

            try:
                self._apply_filter_patterns(host)
            except SkipHostError as e:
                display.debug(e)
                continue

            yield host

    def _new_host(self, props):
        """Return a dictionary of Host info from vSphere API properties"""

        host = {
            'groups': set(),
            'hostvars': {},
            'name': None,
            'props': props,
        }

        host['name'] = self._compose(self.get_option('default_hostname'), host)

        return host

    def _apply_hostvar_patterns(self, host):
        """
        Inflate host with hostvars parsed via hostvar expressions.

        If hostvars.inventory_hostname is set, it clobbers the default name.
        """

        for hostvar, pattern in self.get_option('hostvars').iteritems():
            try:
                hostval = self._compose(pattern, host)
                host['hostvars'][hostvar] = hostval
            except AnsibleError as e:
                display.debug('Hostvar error: %s => %s' % (hostvar, e))
                host['hostvars'][hostvar] = None

        # Clobber the default inventory_hostname if it's set in hostvars
        try:
            old_hostname = host['name']
            new_hostname = host['hostvars'].pop('inventory_hostname')

            if new_hostname:
                display.debug('Overriding hostname: %s => %s' % (
                    old_hostname, new_hostname))
                host['name'] = new_hostname
        except KeyError:
            display.debug("Using default inventory_hostname: %(name)s" % host)

    def _apply_groups_patterns(self, host):
        """Inflate host with groups parsed via grouping expressions"""

        for pattern in self.get_option('groups'):
            group_names = self._compose(pattern, host)
            if isinstance(group_names, (list, set)):
                host['groups'] |= set(group_names)
            else:
                host['groups'].add(group_names)

    def _apply_filter_patterns(self, host):
        """
        Apply all filtering expressions to the host, raising a SkipHostError if
        an expression returns false or itself raises an Exception.
        """

        for pattern in self.get_option('filters'):
            try:
                is_allowed = self._compose(pattern, host)
            except AnsibleError as e:
                raise SkipHostError("Unexpected error: %s" % e)

            if not is_allowed:
                raise SkipHostError('Skipped %s: %s' % (host['name'], pattern))

    def _extract_inventory(self, results):
        """
        Extract a flat, cacheable dictionary of data from results returned by
        the vSphere API. The dictionary consists of extracted properties
        indexed by a pseudo-UUID for the given managed object. The ID looks
        like "vim.VirtualMachine:<some-key>".

        This method would not be necessary if `results` were cacheable, but
        unfortunately it's not -- pyVmomi doesn't play nicely with JSON/Pickle.
        """

        inventory = {}

        for r in results:
            uid = mo_uuid(r.obj)

            display.debug('Processing object %s' % uid)

            inventory.setdefault(uid, {})
            inventory[uid].setdefault('_parent', None)
            inventory[uid].setdefault('resourcePool.summary.name', None)

            # Set properties to their (parsed) value
            for p in r.propSet:
                key = to_text(p.name)
                val = property_value(p.val)

                display.debug('Setting property: %s => %s' % (key, val))
                inventory[uid][key] = val

            # Setting missing properties to None
            for p in r.missingSet:
                key = to_text(p.name)

                display.debug('Setting missing property: %s' % key)
                inventory[uid].setdefault(key, None)  # avoid clobbering

            # Set parentage of VMs/Folder in Folders
            try:
                for child_uid in inventory[uid]['childEntity']:
                    inventory.setdefault(child_uid, {})
                    inventory[child_uid]['_parent'] = uid
            except KeyError:
                pass

            # Set the resource pool name
            try:
                for vm_uid in inventory[uid]['vm']:
                    inventory.setdefault(vm_uid, {})
                    inventory[vm_uid]['resourcePool.summary.name'] = \
                        inventory[uid]['name']
            except KeyError:
                pass

            # Prevent spurious nic updates by omitting NICs without an IP
            try:
                inventory[uid]['guest.net'] = [
                    i for i in inventory[uid]['guest.net'] if i['ipAddress']
                ]
            except KeyError:
                pass

        # Traverse through parent-child relationships to find full 'folder'
        for uid, props in virtual_machines(inventory):
            display.debug('Parsing folder for %s' % uid)

            parents = deque()

            try:
                parent_uid = props['_parent']
                while parent_uid:
                    parents.appendleft(inventory[parent_uid]['name'])
                    parent_uid = inventory[parent_uid]['_parent']
            except KeyError:
                pass

            # Flatten deque to string so it's JSON serializable
            props['folder'] = '/'.join(parents)

        return inventory

    def _execute_search(self):
        """
        Query vSphere for VirtualMachines, ResourcePools, and Folders. This is
        the only method that requires an active vSphere connection.
        """

        with self._socks5(), self._vsphere_connection() as si:
            # Find starting view from which to search
            content = si.RetrieveContent()
            root_node = content.searchIndex.FindByInventoryPath('/')
            container_view = content.viewManager.CreateContainerView(
                container=root_node,
                type=[vim.Folder, vim.ResourcePool, vim.VirtualMachine],
                recursive=True,
            )

            # ObjectSpec defines the starting point for our inventory search
            obj_spec = vmodl.query.PropertyCollector.ObjectSpec()
            obj_spec.obj = container_view
            obj_spec.skip = False

            # TraversalSpec describes how to get to objects of interest
            trav_spec = vmodl.query.PropertyCollector.TraversalSpec()
            trav_spec.name = "traverseEntities"
            trav_spec.path = "view"
            trav_spec.skip = False
            trav_spec.type = container_view.__class__
            obj_spec.selectSet = [trav_spec]

            # PropertySpec describes the properties returned for each type
            prop_specs = [
                vmodl.query.PropertyCollector.PropertySpec(
                    type=vim.Folder,
                    pathSet=[
                        "childEntity",
                        "childType",
                        "name",
                        "tag",
                    ],
                    all=False,
                ),
                vmodl.query.PropertyCollector.PropertySpec(
                    type=vim.ResourcePool,
                    pathSet=[
                        "name",
                        "vm",
                    ],
                    all=False,
                ),
                vmodl.query.PropertyCollector.PropertySpec(
                    type=vim.VirtualMachine,
                    pathSet=[
                        "config.cpuHotAddEnabled",
                        "config.cpuHotRemoveEnabled",
                        "config.hardware.memoryMB",
                        "config.hardware.numCPU",
                        "config.instanceUuid",
                        "config.memoryHotAddEnabled",
                        "config.template",
                        "config.uuid",
                        "config.version",
                        "guest.guestFamily",
                        "guest.guestId",
                        "guest.guestState",
                        "guest.hostName",
                        "guest.net",
                        "guest.toolsRunningStatus",
                        "guest.toolsVersionStatus",
                        "name",
                        "runtime.powerState",
                        "tag",
                    ],
                    all=False,
                ),
            ]

            # FilterSpec wraps everything together
            filterspec = vmodl.query.PropertyCollector.FilterSpec()
            filterspec.objectSet = [obj_spec]
            filterspec.propSet = prop_specs

            pc = content.propertyCollector

            display.debug("Paging through vsphere results...")
            opts = vim.PropertyCollector.RetrieveOptions()
            query = pc.RetrievePropertiesEx(specSet=[filterspec], options=opts)

            results = []
            while query.objects:
                display.debug("... Got %i results" % len(query.objects))
                results += query.objects

                if query.token:
                    display.debug("... Querying next page")
                    query = pc.ContinueRetrievePropertiesEx(token=query.token)
                else:
                    break

            display.debug("Cleaning up container view memory...")
            container_view.Destroy()

            return results

    def _socks5(self):
        """ContextManager for tunneling connections through a SOCKS5 proxy"""

        return SOCKS5Proxy(
            host=self.get_option('proxy_host'),
            port=self.get_option('proxy_port'),
        )

    def _vsphere_connection(self):
        """ContextManager for connecting/authenticating to vSphere"""

        password = self.get_option('password')
        try:
            password = self._compose(password)
        except AnsibleError:
            display.debug("... vSphere password is not templated")

        opts = dict(
            host=self.get_option('hostname'),
            user=self.get_option('username'),
            pwd=password,
        )

        return SmartConnection(**opts)

    def _compose(self, template, variables=None):
        """
        Helper method for plugins to compose variables for Ansible based on
        jinja2 expression and inventory vars
        """

        if variables is None:
            variables = {}

        t = self.templar
        t.set_available_variables(variables)
        return t.template('%s%s%s' % (
            t.environment.variable_start_string,
            template,
            t.environment.variable_end_string,
        ))


class SOCKS5Proxy:
    """Context Manager that monkey-patches socket to use a SOCKS proxy."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._old_socket = None

    def __enter__(self):
        """Monkey-patch socket to use socks5 proxy, but only if host is set."""

        is_proxied = False
        if self.host:
            display.vv('Using proxy %s' % self)

            socks.set_default_proxy(socks.SOCKS5, self.host, self.port)
            self._old_socket = socket.socket
            socket.socket = socks.socksocket
            is_proxied = True
        return is_proxied

    def __exit__(self, type, value, traceback):
        """Restore the original socket"""

        if self._old_socket:
            socket.socket = self._old_socket

    def __repr__(self):
        return "%s(host=%s, port=%i)" % (self.__class__.__name__,
                                         self.host, self.port)


class SkipHostError(Exception):
    """Raise this to indicate a host should be skipped, and why"""
    pass


def mo_uuid(vimobj):
    """Returns a pseudo-UUID for a given vSphere ManagedObject"""

    return to_text(vimobj.__repr__().strip("'"))


def virtual_machines(inventory):
    """Iterate just through the VMs in cacheable data"""

    for uid, props in inventory.iteritems():
        if uid.startswith('vim.VirtualMachine'):
            yield uid, props


def property_value(propval):
    """Extract an Ansible-safe value from the given vSphere property value"""

    if isinstance(propval, str):
        return to_text(propval)

    if isinstance(propval, (int, bool)):
        return propval

    if isinstance(propval, VmomiSupport.Array):
        return [property_value(v) for v in propval]

    if isinstance(propval, vim.vm.GuestInfo.NicInfo):
        return {
            'connected': bool(propval.connected),
            'ipAddress': [str(ip) for ip in propval.ipAddress],
            'macAddress': str(propval.macAddress),
        }

    if isinstance(propval, VmomiSupport.ManagedObject):
        return mo_uuid(propval)

    return None

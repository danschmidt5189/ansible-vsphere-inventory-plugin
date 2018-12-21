# ansible-vsphere-inventory-plugin

Yet another vSphere inventory plugin. This one offers features I've not seen elsewhere:

- Use Jinja2 expressions to extract hostvars, group hosts, and filter hosts out of the inventory.
- Pulls and caches all data from vSphere before applying filters, extractions, groupings, etc.
  - Tested with small inventories (~250 VM). Memory/performance will suffer with larger ones.
  - The same cache may be used to generate different views of inventory for the same vSphere connection.

Expressions can reference (and ultimately modify) the following values for each host:

- `name`: The name of the virtual machine.
- `props`: Raw host properties extracted via the API call. See _execute_search() for schema.
- `hostvars`: Dictionary of hostvars for the host.
- `groups`: Set of groups for the host.

```yml
plugin: vsphere

# Caching
cache: True
cache_plugin: jsonfile
cache_timeout: 0 # never expire

# Extracting Hostvars
hostvars:
  ansible_host: props['guest.net'] | map(attribute='ipAddress') | sum(start=[]) | ipv4('public') | first
  inventory_hostname: props['guest.hostName'] | d(props['name'])
  vsphere_config_hardware_cpuHotAddEnabled: props['config.hardware.cpuHotAddEnabled']
  vsphere_config_hardware_cpuHotRemoveEnabled: props['config.hardware.cpuHotRemoveEnabled']
  vsphere_config_hardware_memoryHotAddEnabled: props['config.hardware.memoryHotAddEnabled']
  vsphere_config_hardware_memoryMB: props['config.hardware.memoryMB']
  vsphere_config_hardware_numCPU: props['config.hardware.numCPU']
  vsphere_config_instanceUuid: props['config.instanceUuid']
  vsphere_config_template: props['config.template'] | bool
  vsphere_config_uuid: props['config.uuid']
  vsphere_config_version: props['config.version']
  vsphere_folder: props['folder']
  vsphere_guest_guestFamily: props['guest.guestFamily']
  vsphere_guest_hostName: props['guest.hostName']
  vsphere_name: props['name']
  vsphere_resourcePool: props['resourcePool.summary.name']
  vsphere_runtime_powerState: props['runtime.powerState']

# Assigning Groups
groups:
  - hostvars['vsphere_guest_guestFamily']
  - hostvars['vsphere_folder'].split('/')

# Filtering Hosts
filters:
  - "'production' in groups"
  - not hostvars['vsphere_config_template']
  - hostvars['ansible_host'] | ipv4('public')
  - hostvars['vsphere_guest_guestFamily'] not in ['windowsGuest']
```

import logging
from cStringIO import StringIO


class ProvisioningException(Exception):
    pass


class Machine(object):

    def __init__(self, hostname, cores, ram_mb):
        assert(cores >= 1 and 256 <= ram_mb <= 99999999)
        self.hostname = hostname
        self.total_cores = cores
        self.total_ram_mb = ram_mb

        self.available_cores = self.total_cores
        self.available_ram_mb = self.total_ram_mb
        self.allocations = list()  # keep track of filled allocations 

    def reserve_special_allocation(self, allocation, instances, config):
        required_cores = allocation.cores * instances
        required_ram = allocation.ram_mb * instances

        if self.available_cores < required_cores:
            return False
        if self.available_ram_mb < required_ram:
            return False

        logging.debug('machine %s accepting special reservation %s (%s/%s) - %s %s',
                      self.hostname, allocation.name, allocation.cores,
                      allocation.ram_mb, instances, config)

        self.available_cores -= required_cores
        self.available_ram_mb -= required_ram
        self.allocations.append(allocation)

        logging.debug('machine %s accepting reservation %s (%s/%s) remains (%s/%s)',
                      self.hostname, allocation.name, allocation.cores, allocation.ram_mb,
                      self.available_cores, self.available_ram_mb)

        return True

    def reserve_allocation(self, allocation):
        if self.available_cores < allocation.cores:
            return False
        if self.available_ram_mb < allocation.ram_mb:
            return False

        logging.debug('machine %s accepting reservation %s (%s/%s)',
                      self.hostname, allocation.name, allocation.cores,
                      allocation.ram_mb)

        self.available_cores -= allocation.cores
        self.available_ram_mb -= allocation.ram_mb
        self.allocations.append(allocation)

        logging.debug('machine %s accepting reservation %s (%s/%s) remains (%s/%s)',
                      self.hostname, allocation.name, allocation.cores, allocation.ram_mb,
                      self.available_cores, self.available_ram_mb)

        return True

    def get_allocation_data(self):
        allocation_data = []
        for alloc in self.allocations:
            if isinstance(alloc, ServicePodAllocation):
                allocation_data.append({
                    'type': 'pod',
                    'alloc': {
                        'type': 'service',
                        'cores': alloc.alloc.cores,
                        'name': alloc.alloc.name,
                        'ram_mb': alloc.alloc.ram_mb,
                        'service_name': alloc.alloc.service_name
                    },
                    'config': alloc.config,
                    'instances': alloc.instances,
                    'cores': alloc.cores,
                    'name': alloc.name,
                    'ram_mb': alloc.ram_mb,
                    'service_name': alloc.service_name
                })
            elif isinstance(alloc, VmAllocation):
                allocation_data.append({
                    'type': 'vm',
                    'cores': alloc.cores,
                    'name': alloc.name,
                    'ram_mb': alloc.ram_mb,
                    'vm_allocs': alloc.vm_allocs
                })
            elif isinstance(alloc, ServiceAllocation):
                allocation_data.append({
                    'type': 'service',
                    'cores': alloc.cores,
                    'name': alloc.name,
                    'ram_mb': alloc.ram_mb,
                    'service_name': alloc.service_name
                })
            else:
                continue
        return allocation_data


class MachineCluster(object):

    def __init__(self, machine_list):
        self.machines = machine_list

    def get_allocation_data(self):
        global_ram = sum([machine.total_ram_mb for machine in self.machines])
        global_cores = sum([machine.total_cores for machine in self.machines])
        avail_cores = sum([machine.available_cores for machine in self.machines])
        avail_ram = sum([machine.available_ram_mb for machine in self.machines])
        num_machines = len(self.machines)

        machines = [{'name': machine.hostname,
                     'total_cores': machine.total_cores,
                     'total_ram': machine.total_ram_mb,
                     'available_cores': machine.available_cores,
                     'available_ram': machine.available_ram_mb,
                     'allocations': machine.get_allocation_data()}
                    for machine in self.machines]

        profiles = self.get_profiles_for_current_allocations()

        return {'global_ram': global_ram,
                'global_cores': global_cores,
                'available_cores': avail_cores,
                'available_ram': avail_ram,
                'num_machines': num_machines,
                'machines': machines,
                'profiles': profiles}

    def get_summary(self):
        global_ram = sum([machine.total_ram_mb for machine in self.machines])
        global_cores = sum([machine.total_cores for machine in self.machines])
        avail_cores = sum([machine.available_cores for machine in self.machines])
        avail_ram = sum([machine.available_ram_mb for machine in self.machines])
        num_machines = len(self.machines)

        summary = StringIO()
        summary.write("\tTotal Machines: %d\n" % num_machines)
        summary.write("\tCluster Total Cores   : %8s\n" % global_cores)
        summary.write("\tCluster Total RAM (MB): %8s\n" % global_ram)
        summary.write("\tCluster Available Cores   : %8s\n" % avail_cores)
        summary.write("\tCluster Available RAM (MB): %8s\n" % avail_ram)
        return summary.getvalue()

    def get_profile_summary(self):
        summary = StringIO()

        machine_profiles = self.get_profiles_for_current_allocations()
        for machine, profile in machine_profiles.iteritems():
            vm_list = []
            service_list = []
            summary.write('\t{}\t'.format(machine))
            for name, vm_config in profile['virtual_machines'].iteritems():
                vm_list.append('{}:{}'.format(name, vm_config.get('num_instances')))
            for name, service_config in profile['services'].iteritems():
                service_list.append('{}:{}'.format(name, service_config.get('workers')))
            summary.write('\n\t\tVMs: {}\n\t\tServices: {}\n'.format(', '.join(vm_list), ', '.join(service_list)))
        return summary.getvalue()

    def get_profiles_for_current_allocations(self):
        profiles = {}   # {profile_name: profile_dict}
        for machine in self.machines:
            machine_profile = {'services': dict(), 'system_overrides': dict(), 'virtual_machines': dict()}
            for alloc in machine.allocations:
                alloc.update_profile_for_allocation(machine_profile)
            profiles['auto-' + machine.hostname] = machine_profile
        return profiles

    def provision_allocations(self, allocation_group):
        # plan special allocations first
        i = 0
        for alloc in allocation_group.special_allocations:
            logging.info('Attempting to fulfill special allocation: %s', alloc)
            # All instances should be fullfilled on one machine
            i = self._fullfill_instance_special_allocation(i, alloc)
            i += 1

        for (allocation, instances) in allocation_group.allocations:
            logging.info('Attempting to fulfill: %s %s', allocation.name, instances)
            i = 0  # current position in machinlist ee
            impossible_to_fullfill = False
            while instances > 0 and not impossible_to_fullfill:
                i = self._fullfill_instance_allocation_balanced(i, allocation)
                if i is None:
                    impossible_to_fullfill = True
                    continue
                else:
                    instances -= 1
                    i += 1

    def _fullfill_instance_special_allocation(self, i, allocation):
        table_len = len(self.machines)
        machine_preference_ordinals = range(i, table_len) + range(0, i)
        for position in machine_preference_ordinals:
            machine = self.machines[position]
            if machine.reserve_allocation(allocation):
                return position
        print 'Didnt fullfill: %s: requires %f/%d' % (allocation.name, allocation.cores, allocation.ram_mb)
        raise ProvisioningException('Could not fullfill %s. Aborting' % allocation.name)

    def _fullfill_instance_allocation_balanced(self, i, allocation):
        table_len = len(self.machines)
        machine_preference_ordinals = range(i, table_len) + range(0, i)
        for position in machine_preference_ordinals:
            machine = self.machines[position]
            if machine.reserve_allocation(allocation):
                return position
        print 'Didnt fullfill: %s: requires %f/%d' % (allocation.name, allocation.cores, allocation.ram_mb)
        raise ProvisioningException('Could not fullfill %s. Aborting' % allocation.name)


class Allocation(object):

    def __init__(self, alloc_name, required_cores, required_ram_mb):
        self.name = alloc_name
        self.cores = required_cores
        self.ram_mb = required_ram_mb

    def __str__(self):
        return "{} ({}/{})".format(self.name, self.cores, self.ram_mb)

    def __repr__(self):
        return self.__str__()

    def update_profile_for_allocation(self, _profile_to_update):
        return


class ServiceAllocation(Allocation):

    def __init__(self, alloc_name, required_cores, required_ram_mb, service_name):
        super(ServiceAllocation, self).__init__(alloc_name, required_cores, required_ram_mb)
        self.service_name = service_name

    def update_profile_for_allocation(self, profile):
        # If there is already an entry for this service type, just
        # increase the number of workers
        existing_instances = profile['services'].get(self.service_name, {}).get('workers', 0)
        if existing_instances:
            profile['services'][self.service_name]['workers'] = existing_instances + 1
        else:
            profile['services'][self.service_name] = {'workers': 1, 'service_overrides': {}}
        return


class ServicePodAllocation(Allocation):

    def __init__(self, alloc, instances, config):
        super(ServicePodAllocation, self).__init__(
            alloc.name,
            alloc.cores * instances,
            alloc.ram_mb * instances)
        self.service_name = alloc.service_name
        self.alloc = alloc
        self.instances = instances
        self.config = config
        assert(self.cores > 0)
        assert(self.ram_mb > 0)

    def update_profile_for_allocation(self, profile):
        # POD allocations must be the only allocation for a given service type in a profile.
        if self.service_name in profile['services']:
            raise ProvisioningException("Attempted to allocate a POD for %s where a service entry already exists",
                                        self.service_name)

        profile['services'][self.service_name] = {'workers': self.instances, 'service_overrides': self.config}
        return

    def __str__(self):
        return '{} instances:{} cores:{} ram:{} cfg:{}'.format(self.name, self.instances, self.cores,
                                                               self.ram_mb, self.config)


class VmAllocation(Allocation):

    def __init__(self, alloc_name, required_cores, required_ram_mb, service_profiles_list):
        super(VmAllocation, self).__init__(alloc_name, required_cores, required_ram_mb)
        self.vm_allocs = service_profiles_list

    def update_profile_for_allocation(self, profile):
        # If there is already an entry for this service type, just
        # increase the number of workers
        existing_instances = profile['virtual_machines'].get(self.name, {}).get('num_instances', 0)
        if existing_instances:
            profile['virtual_machines'][self.name]['num_instances'] = existing_instances + 1
        else:
            profile['virtual_machines'][self.name] = {'num_instances': 1, 'vm_overrides': {}}
        return


def cmp_most_cores(x, y):
    return cmp(y[0].cores, x[0].cores)


class AllocationRequestGroup(object):
    def __init__(self, allocation_list, special_allocations):
        self.allocations = allocation_list
        for alloc in self.allocations:
            assert(isinstance(alloc[1], int))
        self.allocations.sort(cmp=cmp_most_cores)

        self.special_allocations = special_allocations
        for alloc in self.special_allocations:
            assert(isinstance(alloc, ServicePodAllocation))

    def get_summary(self):
        summary = StringIO()
        required_cores_general = sum(alloc.cores * n for (alloc, n) in self.allocations)
        required_ram_general = sum(alloc.ram_mb * n for (alloc, n) in self.allocations)
        num_allocations = len(self.allocations)

        required_cores_special = sum(alloc.cores for alloc in self.special_allocations)
        required_ram_special = sum(alloc.ram_mb for alloc in self.special_allocations)
        num_special_allocations = len(self.special_allocations)

        total_allocations = num_allocations + num_special_allocations
        required_cores = required_cores_general + required_cores_special
        required_ram = required_ram_general + required_ram_special

        summary.write("\tTotal Allocations: %d   (general: %d  special: %d)\n" %
                      (total_allocations, num_allocations, num_special_allocations))
        summary.write("\tRequired Cores   : %-8.1f (general: %-8.1f  special: %-8.1f\n" %
                      (required_cores, required_cores_general, required_cores_special))
        summary.write("\tRequired RAM (MB): %-8.1f (general: %-8.1f  special: %-8.1f\n" %
                      (required_ram, required_ram_general, required_ram_special))
        return summary.getvalue()


class ClusterProvisioner(object):

    def __init__(self, available_machines, allocation_request_group, special_allocations):
        self.machine_cluster = MachineCluster(available_machines)
        self.requested_allocation = AllocationRequestGroup(allocation_request_group, special_allocations)

    def run(self, print_summary=True):
        if print_summary:
            print 'Machine Cluster Summary (Before Allocation)\n' + self.machine_cluster.get_summary()

        prod_allocations = self.requested_allocation
        if print_summary:
            print 'Allocations Requested\n' + prod_allocations.get_summary()

        self.machine_cluster.provision_allocations(prod_allocations)
        if print_summary:
            print 'Machine Cluster Summary (After Allocation)\n' + self.machine_cluster.get_summary()

        if print_summary:
            print '\nProfile Allocation Plan\n'
            print self.machine_cluster.get_profile_summary()

        return self.machine_cluster.get_allocation_data()

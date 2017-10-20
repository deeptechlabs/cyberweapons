import libvirt
import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

def destroy_all():
    vmm = libvirt.open(None)
    for vm in vmm.listAllDomains():
        try:
            if vm.isActive():
                vm.destroy()
        except:
            logging.exception('destorying a  vm')
    vmm.close()

if __name__ == '__main__':
    destroy_all()

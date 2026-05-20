#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/var/log/userdata-sriov-log.out 2>&1
echo "#####################################################"
echo "Echo from config-sriov.sh."
echo "#####################################################"

# subnetCount and SriovStartingInterface are sed-substitution targets.
# user_data replaces them before writing this file to the node, e.g.:
#   sed -i "s/subnetCount/${MULTUS_SUBNET_COUNT}/" /opt/dpdk/config-sriov.sh
#   sed -i "s/SriovStartingInterface/${SRIOV_START_IF}/" /opt/dpdk/config-sriov.sh

modprobe vfio_pci
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
for intf in eth{SriovStartingInterface..subnetCount}; do
  pci_id=$(ls -l /sys/class/net/"$intf" | grep device | cut -d '/' -f 9)
  echo "Binding $intf ($pci_id) to vfio-pci..."
  ip route flush dev "$intf" 2>/dev/null || true
  ip addr flush dev "$intf" 2>/dev/null || true
  ip link set "$intf" down 2>/dev/null || true
  /opt/dpdk/dpdk-devbind.py -u "$pci_id"
  /opt/dpdk/dpdk-devbind.py -b vfio-pci "$pci_id"
done

#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/var/log/userdata-sriov-log.out 2>&1
echo "#####################################################"
echo "Echo from sriov-init.sh."
echo "#####################################################"

if ! [[ -f "/var/tmp/finish_sriov_initialization" ]]; then

  # get-vfio-with-wc.sh and the patch are already written to disk by user_data.
  chmod +x /opt/dpdk/get-vfio-with-wc.sh
  cd /opt/dpdk
  ./get-vfio-with-wc.sh

  systemctl enable config-sriov.service

  echo "Initialization completed..."
  touch /var/tmp/finish_sriov_initialization

else
  echo "Initialization already completed, skipping ..."
fi

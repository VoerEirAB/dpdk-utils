# dpdk-eks-scripts

Scripts and config files for DPDK on self-managed EKS nodes (AL2023 / kernel 6.12).
Fetched by Terraform `user_data` at node boot time.

## Files

```
scripts/
  dpdk-devbind.py           from aws-samples/dpdk-setup-eks
  dpdk-resource-builder.py  from aws-samples/dpdk-setup-eks
  sriov-init.sh             from aws-samples/dpdk-setup-eks, modified
  config-sriov.sh           from aws-samples/dpdk-setup-eks, modified
  get-vfio-with-wc.sh       from amzn/amzn-drivers PR#370, modified for AL2023/kernel6.12
systemd/
  sriov-init.service        from aws-samples/dpdk-setup-eks
  config-sriov.service      from aws-samples/dpdk-setup-eks
patches/
  linux-6.8-vfio-wc.patch   from amzn/amzn-drivers PR#370
  linux-6.12-vfio-wc.patch  from amzn/amzn-drivers PR#370
nodeadm/
  bootstrap.yaml.tmpl       nodeadm NodeConfig template, filled by envsubst at boot
```

## License

MIT-0 files: `dpdk-devbind.py`, `dpdk-resource-builder.py`, `sriov-init.sh`, `config-sriov.sh`, `sriov-init.service`, `config-sriov.service`.

Apache 2.0 files: `get-vfio-with-wc.sh`, `linux-6.8-vfio-wc.patch`, `linux-6.12-vfio-wc.patch`. See `NOTICE`.

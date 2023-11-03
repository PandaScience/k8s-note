## Shell Setup

Best put in `~/.bash_aliases`:

```bash
# if autocompletion does not work already
source <(kubectl completion bash)
alias k=kubectl
complete -o default -F __start_kubectl k

# k8s config
alias k='kubectl'   # pre-configured already in ~/.bashrc
alias kx='kubectl explain'
alias kn='kubectl config set-context --current --namespace' # <namespace>
alias kr='kubectl replace --force -f'
alias kgp='kubectl get pod'

alias less='less -i'

export do="--dry-run=client -o yaml"    # k create deploy nginx --image=nginx $do
export now="--force --grace-period 0"   # k delete pod x $now
```

Vim config `~/.vimrc`

```
" pre-configured
set tabstop=2
set expandtab
set shiftwidth=2

" additional customization
set ai
set hls
set ic
set undofile

" or short
set ts=2 sw=2 et ai hls ic undofile
```

## Misc

### Access binaries from containers

Find ETCD cmdline arguments

```
# on controlplane, find PID of etcd running as pod
ps aux | grep etcd

# find binary
cd /proc/<PID>/root/usr/local/bin
etcd -h
```

### Re-encrypt all existing ones via

```
kubectl get secrets -A -o json | kubectl replace -f -
```

### Access API from pod

https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/

or search for "curl token"

### Move around locally built docker images

```
# on controlplane
docker save -o webapp.tar kodekloud/webapp-color:stable
scp webapp.tar node01:

# on node01
docker load -i webapp.tar
docker load < webapp.tar
```

Deduce pods and namespace from container IDs:

```
# fetch POD ID from here:
crictl ps -id <container-id>

# show pod details incl. namespace
crictl pods -id <pod-id>
```

And other way around

```
# filter and choose pod; copy pod ID
crictl pods --name <part-of-pod-name>

# find container ID
crictl ps --pod <pod-id>

# check binary
crictl inspect <ID> | grep -A5 args
```

## Extracting Secrets

Fast via jq:

```
kubectl get secret safe-secret -o json | jq '.data | map_values(@base64d)'
```

```
kubectl get secret safe-secret -o jsonpath='{.data.<key>}' | base64 -d
```

## Audit logs

Filter for specific namespace

```
cat audit.log | jq 'select(.objectRef.namespace == "citadel") | select(.user.username != "system:node:controlplane")'
```

## Kube-Bench

Install from tarball and use provided config

```
# https://github.com/aquasecurity/kube-bench/blob/main/docs/installation.md#download-and-install-binaries

wget https://github.com/aquasecurity/kube-bench/releases/download/v0.6.2/kube-bench_0.6.2_linux_amd64.tar.gz

tar -xf kube-bench_0.6.2_linux_amd64.tar.gz -C /opt --one-top-level

./kube-bench --config-dir $(pwd)/cfg --config $(pwd)/cfg/config.yaml
```

Patching kubelet service:

1. check config file location
   ```
   systemctl cat kubelet.service
   > Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
   ```
2. add what kube-bench tells you

Only run specific tests:

```
# check files under /etc/kube-bench/cgf/cis-1.20
kube-bench run --targets master
kube-bench run --targets node
kube-bench run --targets etcd
```

## Trivy

Find only critical vulnerabilities with trivy

```
images=('nginx:alpine' 'bitnami/nginx' 'nginx:1.13' 'nginx:1.17' 'nginx:1.16' 'nginx:1.14')
for i in ${images[@]}; do echo $i; trivy --severity CRITICAL $i | grep -i total;  done
```

## AppArmor

AppArmor annotations:

```yaml
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/CONTAINER_NAME: localhost/PROFILE
```

NOTE: for deployments, must go into pod template's metadata!

```
apparmor_parser <file>
aa-status | grep <profile_name>

# check profile - safe option
kubectl exec <pod_name> -- cat /proc/1/attr/current
kubectl exec <pod_name> -- cat /proc/1/attr/apparmor/current

# alternatively (does not work with all container runtimes!)
crictl inspect <ID> | grep apparmor
```

### NetPol

Check connection

```
k exec <from-pod> -- telnet <to-pod>.<namespace>.svc:<port>
```

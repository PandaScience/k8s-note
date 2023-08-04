# CKA Quick Reference

### Essential Exam Preparations & Tips

Only https://kubernetes.io/docs allowed in browser, but multiple tabs!

Read this first:

- https://itnext.io/cks-cka-ckad-changed-terminal-to-remote-desktop-157a26c1d5e
- https://training.linuxfoundation.org/blog/update-on-certification-exam-proctoring-migration
- https://killercoda.com/kimwuestkamp/scenario/cks-cka-ckad-remote-desktop
- https://docs.linuxfoundation.org/tc-docs/certification/tips-cka-and-ckad
- https://docs.linuxfoundation.org/tc-docs/certification/faq-cka-ckad-cks
- https://syscheck.bridge.psiexams.com/

Additional training:

- Killer.sh Exam Simulator (comes with exam)
- KillerCoda Scenarios: https://killercoda.com/killer-shell-cka
- Cilium Network Editor: https://editor.networkpolicy.io

Important pages:

- https://kubernetes.io/docs/reference/networking/ports-and-protocols/
- https://kubernetes.io/docs/reference/kubectl/cheatsheet/
- https://kubernetes.io/docs/reference/kubernetes-api/
- https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/

Important paths:

| Path                | Content                      |
| ------------------- | ---------------------------- |
| Static Pods         | `/etc/kubernetes/manifests`  |
| Certificates & Keys | `/etc/kubernetes/pki[/etcd]` |
| kubelet config      | `/var/lib/kubelet`           |
| ETCD data           | `/var/lib/etcd`              |
| CNI config          | `/etc/cni/net.d`             |
| CNI bin             | `/opt/cni/bin`               |

### Memorize

Bash aliases → don't use `.bashrc` if you change it often, because you cannot
simply do `source ~/.bashrc` without breaking your terminal, but you can source
`~/.bash_aliases` no matter if there are only aliases or also exports. It's
also sourced by `~/.bashrc` automatically by default if it exists.

```
# ~/.bash_aliases
alias k='kubectl'
alias kx='kubectl explain'
alias kn='kubectl config set-context --current --namespace' # <namespace>
alias kr='kubecrl replace --force -f'

export do="--dry-run=client -o yaml"    # k create deploy nginx --image=nginx $do
export now="--force --grace-period 0"   # k delete pod x $now
```

Proper minimal vim config `~/.vimrc`

```
" ~/.vimrc

" pre-configured
set tabstop=2
set expandtab
set shiftwidth=2

" additional customization
set ai
set hls
set ic
set undofile
```

**NOTE:** When copy&pasting (using <kbd>CTRL+C</kbd> in browser but
<kbd>CTRL+SHIFT+V</kbd> in terminal vim) it will break indentation. You need to
do `:set paste` before, then copy, then easiest to save and close vim and open
the file again.

Why - You might ask? Because `paste` resets `expandtab`, which will inevitably
mess with any lines you will change thereafter and lead to really hard to find
issues when trying to deploy these files!

Also make sure you understand the `:retab` command...just in case ;-)

### Help without web documentation

```
kubectl explain clusterrole.rules.verbs
kubectl create deployment --help
```

### Working with different contexts

Switch contexts

```
kubectl config get-contexts
kubectl config use-context <cluster>
```

Set kubectl default namespace (like with the
[kubens](https://github.com/ahmetb/kubectx) tool)

```
kubectl config set-context --current --namespace=<NAMESPACE>
```

## Core Concepts

### Pods

Generally useful commands

```
kubectl get pods
kubectl get pods -o wide
kubectl get pods --no-headers | wc -l

kubectl describe pod <pod>

kubectl run nginx --image=nginx

kubectl appply  -f manifest.yaml
kubectl create  -f manifest.yaml
kubectl replace -f manifest.yaml [--force]

kubectl delete pod webapp [--force]

kubectl run redis --image=redis --dry-run=client -o yaml > redis.yaml

kubectl edit pod redis
kubectl set image pod/redis redis=redis
```

Show only RUNNING pods

```
kubectl get pods -A --field-selector=status.phase==Running
```

Show images of several equally-named pods (part of pod name sufficient to list all)

```
kubectl describe pod newpod | grep Image
```

Patch image of running pod

```
kubectl set image pod/redis redis=redis
```

### ReplicaSets

```
kubectl get replicaset
kubectl get rs
```

Show images

```
kubectl get rs -o wide  # -> IMAGES column
```

Scaling

```
kubectl scale --replicas=N -f replicaset.yaml
kubectl scale --replicas=N replicaset repset-name
```

Re-create

```
kubectl get rs new-replica-set -o yaml > rs.yaml
kubectl delete rs new-replica-set
kunectl create -f rs.yaml
```

### Deployments

```
kubectl get deployment
kubectl get deploy
```

Create

```
kubectl create deployment --image=nginx nginx

# from v1.19+ able to set replicas
kubectl create deployment --image=nginx nginx --replicas=4
```

Check image

```
kubectl get deploy -o wide
```

### Services

Show ClusterIP, External IP, Ports and selectors

```
kubectl get service
kubectl get svc
```

Show labels

```
kubectl describe service --show-labels
```

Check mistakenly selected pods by looking at endpoints in describe.

### Namespaces

Show namespaces

```
kubectl get namespace
kubectl get ns
```

Search particular namespace

```
kubectl get pods -n mynamespace
```

Permanently switch namespaces:

```
kubectl config set-context --current --namespace=dev
```

Show pods in all namespaces

```
kubectl get pods --all-namespaces
kubectl get pods -A
```

### Declarative vs Imperative Commands

If command unknown, run e.g. `kubectl run --help`!

#### Pods

Create an NGINX Pod

```
kubectl run nginx --image=nginx -l/--labels key=value
```

Generate POD Manifest YAML file (`-o yaml`) but don't create it (`--dry-run`)

```
kubectl run nginx --image=nginx --dry-run=client -o yaml
```

Create pod and "expose" on container port 8080

```
kubectl run custom-nginx --image=nginx --port=8080
```

Create pod and expose with service (ClusterIP)

```
kubectl run httpd --image httpd:alpine --expose --port 80
```

#### Deployments

Create a deployment

```
kubectl create deployment --image=nginx nginx
```

Generate Deployment YAML file (`-o yaml`) but don't create it (`--dry-run`)

```
kubectl create deployment --image=nginx nginx --dry-run=client -o yaml
```

Generate Deployment with 4 Replicas

```
kubectl create deployment nginx --image=nginx --replicas=4
```

Scale a deployment

```
kubectl scale deployment nginx --replicas=4
```

Save the YAML definition to a file and modify

```
kubectl create deployment nginx --image=nginx --dry-run=client -o yaml > nginx-deployment.yaml
```

#### Service

**Ex.1:** Create a Service named redis-service of type ClusterIP to expose pod
redis on port 6379

(This will automatically use the pod's labels as selectors!)

```
kubectl expose pod redis --port=6379 --name redis-service
```

or alternatively

(This will not use the pods labels as selectors, instead it will assume
selectors as app=redis. You cannot pass in selectors as an option. So it does
not work very well if your pod has a different label set. Better generate the
file and modify the selectors before creating the service)

```
kubectl create service clusterip redis --tcp=6379:6379
```

**Ex.2:** Create a Service named nginx of type NodePort to expose pod nginx's
port 80 on port 30080 on the nodes:

(This will automatically use the pod's labels as selectors, but you cannot
specify the node port. You will have to generate a definition file and then add
the node port in manually before creating the service with the pod.)

```
kubectl expose pod nginx --type=NodePort --port=80 --name=nginx-service --dry-run=client -o yaml
```

or alternatively

(This will not automatically use the pods labels as selectors)

```
 kubectl create service nodeport nginx --tcp=80:80 --node-port=30080 --dry-run=client -o yaml
```

## Scheduling

### Manual Scheduling

Check for key pods (e.g. coredns, etcd-controlplane, kube-proxy, kube-controller-manager, kube-scheduler):

```
kubectl get pods --namespace kube-system
```

### Labels & Selectors

Get objects with specific labels

```
kubectl get pods -l/--selector key=value
```

```
kubectl get pods -l app=App1
kubectl get all -l env=prod
kubectl get all -l env=prod,bu=finance,tier=frontend
```

List label values of resources / pods for specific label key as column

```
kubectl get pods -L app [-L key2 -L key3 ...]
```

### Taints & Tolerations

Check taints

```
kubectl describe node kubemaster | grep Taint
```

Create taints

```
kubectl taint nodes <node> key=value:effect
kubectl taint nodes node01 spray=mortein:NoSchedule
```

Remove taints

```
kubectl taint nodes node01 spray=mortein:NoSchedule-
```

### Node Selectors & Affinity

Node labels used in selectors

```
kubectl label nodes <node> key=value

kubectl get nodes --show-labels
```

### DaemonSets

No CLI command to create DaemonSets! Use the one for Deployment instead and modify:

```
kubectl -n kube-system create deploy --image=registry.k8s.io/fluentd-elasticsearch:1.20 --dry-run=client -o yaml > ds.yaml
```

- replace `kind: DaemonSets`
- remove `replicas` and `strategy` fields

### Static Pods

Always can tell by the name, which is suffixed with the node name, e.g.
`podname-controlplane` or `podname-workernode1`

Check if pod is static from manifest:

```
kubectl describe pods
```

➜ search for `ownerReferences.kind = Node` (instead of ReplicaSet for instance)

Find static pod path

```
ps aux | grep kubelet
```

Search for `--config=<path>` and check config file for `staticPodPath` or
search for `--pod-manifest-path=<path>`.

Create static pod

```
kubectl run static-busybox --image busybox --dry-run=client -o yaml --command -- sleep 1000 > /etc/kubernetes/manifests/busybox.yaml
```

Note: creating, updating and deleting takes a while till it's visible in kubectl

### Custom Scheduler

Check which scheduler was active on specific pod

```
kubectl get event -o wide
```

## Logging and Monitoring

Show metrics server data

```
kubectl top node
kubectl top pod
```

Show logs of container in pod

```
kubectl logs -f <podname> <container>
```

## App Lifecycle Management

### Rolling Updates & Rollbacks

Deployment Rollouts

https://www.alibabacloud.com/blog/pause-resume-and-scale-kubernetes-deployments_595019

```
kubectl rollout status deployment app

# pause
# only way to reliably see paused deployments is via describe -> Conditions.Progressing = DeploymentPaused
kubectl rollout pause deployment app

# do changes and record them (this will put the command in the change-cause field)
kubectl set image deployment app busybox=busybox --record
kubectl scale deployment app --replicas=5

# resume
kubectl rollout resume deployment app
```

Show history

```
kubectl rollout history deployment app
```

Rollback

```
kubectl rollout undo deployment app
```

Manually set a description why a change with the current rollout happened

```
kubectl annotate deployment app kubernetes.io/change-cause="version change from 1.16.0 to latest" --overwrite=true
```

**NOTE:** `--record` has been deprecated and will be removed in the future

### Commands and Arguments

Pass arguments to containers or change command

```
kubectl run app --image <image> -- <arg1> <arg2>
kubectl run app --image <image> --command -- <cmd> <arg1> <arg2>
```

### Config Maps

Create from literals

```
kubectl create configmap app-config --from-literal=APP_COLOR=blue --from-literal=APP_MODE=prod
```

Create from file

```
kubectl create configmap app-config --from-file=app_config.properties
```

Note: this will create a data entry with name of the file!

```yaml
apiVersion: v1
data:
  test.dat: |
    a=b
    c=d
kind: ConfigMap
metadata:
  creationTimestamp: null
  name: myconfigmap
```

#### Secrets

Create secret from literals or from file

```
kubectl create secret generic app-secret --from-literal=DB_Host=mysql --from-literal=DB_User=root --from-literal=DB_Password=paswrd
kubectl create secret generic app-secret --from-file=app_secret.properties
```

Specify type: always use generic (except for TLS or docker registry) then one
of the types ➜ `opaque`, `basic-auth`, `ssh-auth`, `tls`. If omitted `opaque`
is set as default

```
kubectl create secret generic <name> --type <type> --from-file/--from-literal
```

## Cluster Maintenance

### OS Upgrades

Evict pod and mark unschedulable (=drain) (implies cordon)

```
kubectl drain <node>
kubectl drain <node> --ignore-daemonsets
```

Only mark node unschedulable, doesn't affect existing pods on that node

```
kubectl cordon <node>
```

Release node so pods can be scheduled again

```
kubectl uncordon <node>
```

Upgrade (first) control plane node

```
apt install kubeadm=1.27.0-00
kubeadm upgrade plan v1.27.0
kubeadm upgrade apply v1.27.0
```

Upgrade other control plane / worker nodes using instead

```
kubeadm upgrade node
```

Upgrade kubelets on all nodes

```
apt install kubelet=1.27.0-00
system restart kubelet
```

Check versions (shows kubelet version, not apiserver for control plane!)

```
kubectl get nodes
```

Check (api) server & client versions

```
kubectl version --short
```

Check latest -available- versions

```
kubeadm upgrade plan | grep remote
```

### Kubeadm upgrade (short)

Check OS (assume result = ubuntu -> use apt)

```
cat /etc/_release_
```

Update control plane

```
kubectl drain controlplane

apt update
apt-cache madison kubeadm | head

apt-mark unhold kubeadm
apt install kubeadm=1.27.0-00
kubeadm version
apt-mark hold kubeadm

kubeadm upgrade plan v1.27.0
kubeadm upgrade apply v1.27.0

apt-mark unhold kubelet
apt install kubelet=1.27.0-00
apt-mark hold kubelet

systemctl daemon-reload
systemctl restart kubelet

kubectl uncordon controlplane
```

- Repeat for other control plane and worker nodes, but use `kubeadm upgrade node`
  instead of `kubeadm upgrade apply`

Exam note: if only one worker nodes available, untaint controlplane for temp. scheduling

### Backup & Restore

Get ETCD information like

- ETCD version

  ```
  kubectl -n kube-system describe pod etcd | grep Image
  ```

- ETCD address

  ```
  kubectl -n kube-system describe pod etcd | grep -- --listen-client-urls
  ```

- ETCD server certificate

  ```
  kubectl -n kube-system describe pod etcd | grep -- --cert-file
  ```

- ETCD CA certificate

  ```
  kubectl -n kube-system describe pod etcd | grep -- --trusted-ca-file
  ```

NOTE: All `etcd` commands require the following flags (will be left out below)...

```
--endpoints=https://127.0.0.1:2379 \ # (not required if using defaults)
--cacert=/etc/etcd/ca.crt \
--cert=/etc/etcd/etcd-server.crt \
--key=/etc/etcd/etcd-server.key
```

Set `etcdctl` API version globally

```
export ETCDCTL_API=3
```

ETCD snapshots

```
etcdctl snapshot save snap.db
etcdctl snapshot status snap.db
```

ETCD restore (when running as pod)

```
etcdctl snapshot restore snap.db --data-dir /var/lib/etcd-from-backup

#configure etcd.service to use new datadir
vim /etc/kubernetes/manifests/etcd.yaml -> adapt etcd-data volume: volumes.hostPath.path = <new_path>
```

ETCD restore (when running as service)

```
etcdctl snapshot restore snap.db --data-dir /var/lib/etcd-from-backup

# find systemd unit file
sytemctl cat etcd
# edit systemd unit file and adapt data dir
vim /etc/systemd/system/etcd.service

# set correct permissions
chown -R etcd:etcd /var/lib/etcd-from-backup

systemctl daemon-reload
systemctl etcd restart
```

**NOTE:** Not clear if it is essential to stop kube-apiserver, kube-scheduler
and/or kube-controller-manager services or pods. In the labs / test exam they
did just move (and hence effectively delete) the static pods of controlplane
componenets from `/etc/kubernetes/manifests`.

**NOTE:** In the simulator they claim: _"Don't use snapshot status because it
can alter the snapshot file and render it invalid."_ - couldn't find a reference
for that.

### ETCD Maintenance

Check if ETCD cluster uses stacked or external topology
(➜ stacked in case you see etcd pods on control plane nodes, otherwise external,
provided you are given a working cluster)

```
kubectl get pods -n kube-system
```

Explicitly verify external ETCD

- on control plane check static pod configurations in `/etc/kubernetes/manifest`
  ➜ no etcd file? ➜ definitely not stacked
- check ETCD server IP (see below): if not `localhost`, then external

Find IP of external ETCD

```
kubectl describe pods -n kube-system kube-apiserver | grep -- --etcd-server
```

Find data directory of stacked ETCD (as pod) (default: `/var/lib/etcd`)

```
kubectl describe pod -n kube-system etcd | grep -A5 etcd-data
```

Find data directory of external ETCD (as service) (default: `/var/lib/etcd-data`)

```
systemctl list-unit-files | grep etcd
systemctl cat etcd.service
```

Check number of ETCD nodes

```
etcdctl --endpoints=<IP> --cacert=... member list
```

## Security

### TLS Certificates

Important paths:

- `/etc/kubernetes/manifests/*.yaml`
- `/etc/kubernetes/pki/*.crt`
- `/etc/kubernetes/pki/etcd/*.crt`

### Certificate API

Check https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user

Create user key and CSR:

```
openssl genrsa -out jane.key 2048
openssl req -new -key jane.key -subj "/CN=jane" -out jane.csr
```

Create CSR object

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: myuser
spec:
  request: <base64 string>
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400 # one day
  usages:
    - client auth
```

CSR in field needs to be base64-encoded and free of new-lines!

```
cat jane.csr | base64 | tr -d "\n"
cat jane.csr | base64 -w 0
```

Extract CSR from request:

```
kubectl get csr agent-smith -o json | jq -r '.spec.request' | base64 -d | openssl req -noout -text
```

Check requested groups:

```
kubectl get csr agent-smith -o json | jq '.spec.groups'
```

Approve/reject CSR:

```
kubectl get csr
kubectl certificate approve jane
kubectl certificate deny jane
```

Delete CSR

```
kubectl delete csr <csr>
```

Extract certificate after approval:

```
kubectl get csr jane -o yaml

# copy status.certificate block

echo "<block content>" | base64 -d
```

### Kubeconfig

Show configuration (i.e. content of kubeconfig)

```
kubectl config view
```

Change context

```
kubectl config use-context admin@prod
```

### Authorization

Check configured authorization modes

```
kubectl describe pod kube-apiserver-controlplane -n kube-system | grep -- --authorization-mode
```

### RBAC

Working with roles

```
kubectl get|describe roles
kubectl get|describe rolebindings
```

Create Roles

```
kubectl create role foo --verb=get,list,watch --resource=pods,pods/status
```

Create RoleBindings

```
# same with --clusterrole instead of --role
# multiple --user possible
kubectl create rolebinding <name> --role <role> --user <user>
kubectl create rolebinding <name> --role <role> --group <group>
kubectl create rolebinding <name> --role <role> --serviceaccount <SA>
```

Checking access

```
kubectl auth can-i create deployments
kubectl auth can-i create deployments --as dev-user
kubectl auth can-i create deployments --as dev-user --namespace test

kubectl auth can-i create deployments --as system:serviceaccount:dev:dev-sa
```

Run command as specific user (configured in kubeconfig)

```
kubectl get pods --as <user>
```

### Cluster-scoped Resources

Get full list of namespaced or cluster-scoped resources

```
kubectl api-resources --namespaced=true|false [-o wide]
```

### Service Accounts

Create service accounts (token will not be created automatically anymore!)

```
kubectl create serviceaccount <name>
kubectl create sa <name>
```

Create token

```
kubectl create token <SA-name> [--duration=99h]

# more details with
kubectl create token <SA-name> -o yaml
```

NOTE: How to delete token? Open issue: https://github.com/kubernetes/kubectl/issues/1237

**[DEPRECATED]** Extract token for use as authorization bearer token in REST calls

```
kubectl get secret <sa-name>-token-<random-chars> -o json | jq 'data.token' | base64 -d
```

Assign service accounts to existing resources

```
kubectl set serviceaccount deploy/<deployment> <service-account>
```

Decode a token

```
jq -R 'split(".") | select(length > 0) | .[0],.[1] | @base64d | fromjson' <<< <TOKEN>
```

### Image Security

Secret for private Docker registry

```
kubectl create secret docker-registry \
--docker-username=<username> \
--docker-password=<password> \
--docker-email=<email> \
--docker-server=<server:port> \
<secret-name>
```

### Security Contexts

Check user

```
kubectl exec <pod> -- whoami
```

Check security context

```
kubectl get pod -o yaml | grep security
```

### NetworkPolicies

List NetworkPolicies

```
kubectl get networkpolicies
kubectl get netpol
```

Create NetworkPolicies ➜ use template from docs:
https://kubernetes.io/docs/concepts/services-networking/network-policies/

Default deny all ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

Default permit all ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
spec:
  podSelector: {}
  ingress:
    - {}
  policyTypes:
    - Ingress
```

### Kubectx

List all/current contexts

```
kubectx
kubectx -c
```

Switch context

```
kubectx <context>
```

Switch to previous context

```
kubectx -
```

### Kubens

Switch to namespace

```
kubens <namespace>
```

Switch back

```
kubens -
```

## Storage

### PV

Creation via manifest: https://kubernetes.io/docs/concepts/storage/persistent-volumes/#persistent-volumes

```
kubectl get persistentvolume
kubectl get pv
```

### PVC

Creation via manifest: https://kubernetes.io/docs/concepts/storage/persistent-volumes/#persistentvolumeclaims

```
kubectl get pvc
```

### Storage Classes

Creation via manifest: https://kubernetes.io/docs/concepts/storage/storage-classes/#the-storageclass-resource

```
kubectl get storageclass
kubectl get sc
```

Identify SC that does not support dynamic provisioning

```
kubectl get sc | grep kubernetes.io/no-provisioner
```

## Networking

### Routing

Show interfaces on host

```
ip link
ip addr
```

Assign ip to interface

```
ip addr add 192.168.1.10/24 dev eth0
```

Show / Create routes on host

```
ip route # or just "route"
ip route add 192.168.2.0/24 via 192.168.1.1
ip route add default via 192.168.1.1
```

Allow package forwarding

```
echo 1 < /proc/sys/net/ipv4/ip_forward
```

or persist with

```
echo "net.ipv4.ip_forward" >> /etc/sysctl.conf
```

### DNS

Search for IPs

```
nslookup www.google.com   # ignores /etc/hosts, only queries DNS server

dig www.google.com
drill www.google.com
```

Mnemonic: "drill if you can, dig if you have to, nslookup if you must"

Inverse search:

```
whois <IP>
```

### Network Namespaces

NOTE: `ip netns` doesn't work by default. Need some hack first:

- https://unix.stackexchange.com/questions/714951/why-is-my-namespace-not-detected
- https://www.baeldung.com/linux/docker-network-namespace-invisible

List and create new network namespaces

```
ip netns
ip netns add <name>
```

Execute in namespaces from host-side

```
ip netns exec <name> ip link
ip -n <name> ip link
```

Same for ARP and routing tables

```
ip netns exec <name> arp
ip netns exec <name> route
```

Link two namespaces

```
# create link
ip link add veth-red type veth peer name veth-blue

# assign virtual eth interfaces to namespaces
ip link set veth-red netns red
ip link set veth-blue netns blue

# add IP
ip -n red addr add 192.168.15.1/24 dev veth-red
ip -n blue addr add 192.168.15.2/24 dev veth-blue

# bring up interfaces
ip -n red link set veth-red up
ip -n blue link set veth-blue up

# test connection
ip netns exec red ping 192.168.15.2
```

Create virtual switch to link multiple namespaces

```
# create bridge
ip link add v-net-0 type bridge
ip link set dev v-net-0 up

# connect all virtual eth to it
ip link add veth-red type veth peer name veth-red-br
ip link add veth-blue type veth peer name veth-blue-br
ip link add veth-green type veth peer name veth-green-br

# connect to namespaces
ip link set veth-red netns red
ip link set veth-blue netns blue
ip link set veth-green netns green

# attach other end to vswitch
ip link set veth-red-br master v-net-0
ip link set veth-blue-br master v-net-0
ip link set veth-green-br master v-net-0

# add IP
ip -n red addr add 192.168.15.1/24 dev veth-red
ip -n blue addr add 192.168.15.2/24 dev veth-blue
ip -n green addr add 192.168.15.3/24 dev veth-green

# bring up interfaces
ip -n red link set veth-red up
ip -n blue link set veth-blue up
ip -n green link set veth-green up

# add host (if required) by assigning an IP to the bridge
ip addr add 192.168.15.5/24 dev v-net-0
```

Let containers access LAN through host's ethernet port

```
# add gateway
ip netns exec blue ip route add 192.168.0.1/24 via 192.168.15.5

# enable NAT
iptables -t nat -A POSTROUTING -s 192.168.15.0/24 -j MASQUERADE
```

Same for internet

```
# add default gateway
ip netns exec blue ip route add default via 192.168.15.5
```

Let outside world connect to webapp on blue network namespace

```
iptables -t nat -A PREROUTING --dport 80 --to-destination 192.168.15.2:80 -j DNAT
```

### Docker Networking

Different kinds of networks in docker

```
docker run --network none nginx
docker run --network host nginx
docker run --network bridge nginx
```

List existing networks

```
docker network ls
```

View network device on host

```
ip link show docker0
ip addr show docker0
```

Show container networking details (-> SandboxID = network namespace)

```
docker inspect <container_ID> -f "{{json .NetworkSettings}}" | jq
```

Show port mapping rules

```
iptables -nvL -t nat
```

### CNI 1

Only place to find CNI installation commands in official docs (for exam):

https://v1-22.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/#steps-for-the-first-control-plane-node (step 2)

Internal IPs

```
kubectl get nodes -o wide
```

Find correct interfaces

- `eth` always "physical" interfaces
- `lo` = loopback
- `veth` for tunnelling between host and pod network, connetcted to bridges

➜ check to which interface the veths are connected, e.g. "master cni0"

```
ip link
ip addr
ip addr show type bridge
ip route
```

Check listening ports in use

```
ss -tulpen
netstat -tulpen
netstat -tulpen | grep kube-scheduler
```

Check number of active connections (e.g. for ETCD with multiple possible ports,
one for all control plane components and one for internal ETCD-cluster connectivity)

```
netstat -tulpen | grep etcd
netstat -apn | grep etcd
```

Check for non-standard CNI configuration

(NOTE: https://stackoverflow.com/questions/72106699/is-cni-bin-dir-still-effective-on-v1-24-or-any-replace-document-exist)

```
ps aux | grep kubelet | grep -- "--cni-conf-dir"
ps aux | grep kubelet | grep -- "--cni-bin-dir"
```

CNI configuration (default path)

```
cat /etc/cni/net.d/10-bridge.conf
```

### CNI 2

Identify container runtime endpoint

```
# search for EnvironmentFile=<path>
systemctl cat kubelet

# inspect this file, default:
cat /var/lib/kubelet/kubeadm-flags.env | grep -- --container-runtime-endpoint
> unix:///var/run/containerd/containerd.sock
```

Alternatively:

```
ps aux | grep kubelet | grep container-runtime
```

Default CNI binary path: `/opt/cni/bin`

Check available plugins:

```
ls /opt/cni/bin
```

Identify CNI in use:

```
ls /etc/cni/net.d/
```

Identify pod IP range (example: weave)

```
kubectl get daemonset -n kube-system weave-net | grep -i IPALLOC_RANGE

# or
kubectl logs -n kube-system <weave-pod> | grep ipalloc-range
```

Identify default gateway FOR PODS! -> don't do `route` on nodes, it's the wrong answer!

```
kubectl run busybox --image=busybox -- sleep 1000
kubectl exec -it busybox -- route
```

Identify IP range for nodes

```
# find one node's IP in cluster
kubectl get nodes -o wide

# check interface, search for this IP and CIDR range listed below
ip addr | grep <IP>
```

Identify IP range for Services

```
kubectl get pod -n kube-system kube-apiserver-controlplane -o yaml | grep service-cluster-ip-range
```

Identify proxy type in use

```
kubectl logs -n kube-system kube-proxy-POD | grep proxy
```

Save iptables rules on a specific node created for a specific service

```
ssh cluster1-node2 iptables-save | grep my-service
```

### DNS in Kubernetes

Check DNS settings in cluster

```
cat /var/lib/kubelet/config.yaml | grep -A2  clusterDNS
```

Check FQDN of a host (all point to same)

```
host web-service
host web-service.default
host web-service.default.svc
host web-service.default.svc.cluster.local
```

Check DNS server on host -> should point to kube-dns service's IP

```
cat /etc/resolv.conf
```

Check CoreDNS config file path

```
kubectl -n kube-system describe deployments.apps coredns | grep -A2 Args
```

Identify root domain/zone

```
kubectl describe configmap -n kube-system coredns
```

Check DNS after exposing a pod/deployment via ClusterIP service

```
kubectl run test-nslookup --image=busybox:1.28 --rm -it --restart=Never -- nslookup nginx-resolver-service
```

Check pod IP DNS entries

```
kubectl run nslookup --image=busybox:1.28 --rm -it --restart=Never -- nslookup <P-O-D-I-P.default.pod>
```

Check pod IP
kubeadm config print init-defaults

### Ingress

```
kubectl create ingress <ingress-name> --rule="host/path=service:ports
```

Multiple rules plus annotation

```
kubectl create ingress -n app-space ingress-rule \
--rule "/wear=wear-service:8080" \
--rule "/watch=video-service:8080" \
--annotation "nginx.ingress.kubernetes.io/rewrite-target=/"
```

## Advanced kubectl commands using JSON PATH

List single information

```
kubectl get pods -o=jsonpath='{.items[0].spec.containers[0].image}'
```

List multiple information as new lines

```
kubectl get nodes -o=jsonpath='{.items[*].metadata.name}{"\n"}{.items[*].status.capacity.cpu}'
```

List multiple information as proper table via loops

```
kubectl get nodes -o=jsonpath='{range .items[*]} {.metadata.name}{"\t"}{.status.capacity.cpu}{"\n"} {end}'
```

Print custom columns as alternative for tables

```
kubectl get nodes -o=custom-columns=<COLUMN_NAME>:<JSON PATH>
kubectl get nodes -o=custom-columns=NODE:.metadata.name, CPU:.status.capacity.cpu
```

Sort kubectl output

```
kubectl get nodes --sort-by=.metadata.name
kubectl get nodes --sort-by=.status.capacity.cpu
```

### Troubleshooting

Check logs of crashed pods

```
kubectl logs <podname> --previous
```

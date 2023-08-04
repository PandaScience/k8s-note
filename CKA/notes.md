# CKA Notes

## 1. Introduction

- 2h exam
- CKAD, CKA, CKS

## 2. Core Concepts

### Cluster Architecture

- dockerd, containerd or rkt as container runtimes
- master nodes vs worker nodes

control plane:

- ETCD cluster: HA key-value store
- scheduler: pods go where? taints, tolerations, capacities, etc.
- controller manager: responsible for different administration tasks (node controller, replication controller, ...)
- kube-apiserver: exposes k8s api to external users and controllers, communication with worker nodes via kubelet

worker:

- kubelet: agent managing containers on nodes, talks to control plane
- kube-proxy: ensures rules for inter-node communication

### Docker vs ContainerD

k8s built to orchestrate docker -> now: CRI (by OCI -> imagespec, runtimespec)

Docker not compatible with CRI -> dockershim -> removed in 1.24 (containerd standard still supported)

containerd is now a independent CNCF project -> CLI tool `ctr` -> not user-friendly,
better use docker-like CLI `nerdctl`

`crictl` maintained by k8s community compatible with all CRI based runtimes

-> best nerdctl, ctr or crictr for debugging & troubleshooting in KodeKloud

### ETCD

- key-value store instead of table-based DB (relational)
- port 2379
- comes with `etcdctl` CLI
- version 3.1 (watch API v2 vs v3! -> different CLI)

```
etcdctl --version
etcdctl set|put key value  # v2 vs v3
etcdctl get key
etcdctl get / --prefix --keys-only --cert=... --cacert=... --key=...
```

- stores information of entire cluster
- change considered complete if updated in etcd cluster

- manual setup: download tarball & install binary directly on master node
- setup via kubeadm: installed as pod in kube-system
- important: advertise-client-urls https://${INTERNAL_IP}:2379

High-Availability:
https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/ha-topology/

- stacked: etcd run on control plane nodes
  - (i): each etcd member only communicates with kube-apiserver of the same node
  - pro: easier to set up and manage replication
  - con: if control plane node goes down not only apiserver, but also one etcd instance is lost
  - -> more than 1 control plane node is mandatory!
- external: etcd nodes run on dedicated nodes, i.e. not on control plane
  - (i): each etcd member can communicate with every kube-apiserver on each control plane node
  - pro: decoupling of both clustersm, therefore less impact when a node goes down
  - con: requires twice the number of hosts as stacked HA topology
  - -> min. of 3 hosts for control plane and etcd cluster is recommended for proper HA.
  - (!): will not be able to see ETCD pods with kubectl!

### Kubeapi

- kubectl basically does POST requests against kubeapi

responsible for:

- user authentication
- request validation
- data retrival
- ETCD updates (only thing that talks to ETCD!)
- scheduling
- kubelets

Options:

```
# kubeadm
cat /etc/kubernetes/manifests/kube-apiserver.yaml

# manual
cat /etc/systemd/system/kube-apiserver.service

# process
ps -aux | grep kube-apiserver
```

### Kube Controller Manager

- controller continuously monitors status of components and brings it to desired state

Node Controller

- monitor period 5s
- grace period 40s -> marking unreachable
- pod eciction timeout 5m -> if not up after, remove pods to other node

Controllers for other resources - all installed in Kube Controller Manager

- Deployment-Controller
- Namespace-Controller
- Endpoint-Controler
- Job-Controller ....

By default all enabled, but can be selectively disabled.

### Scheduler

only decides where a pod goes but doesn't place them: that's done by the kubelet

1. filter nodes - taints, tolerations,...
2. rank nodes - priority function (remaining resources)

```
cat /etc/kubernetes/manifests/kube-scheduler.yaml
ps -aux | grep kube-scheduler
```

### Kubelet

always needs to be manually installed! (even when deploying with kubeadm)

- register node
- create pod
- monitor pods

### Kubeproxy

Deployed as DaemonSet

- internal IPs may change, so how to communicate reliably?
- services get their own IP assigned! (service = virtual component)
- proxy created IPtables rules on each node to forward services to ports

### Pods

Kubelet does not direcly deploy containers.

Pod is smallest object in K8s, represents a single application but can contain multiple containers

Pod manifests always contain at least:

```
apiVersion:
kind:
metadata:
spec:
```

Uses Dockerhub as registry by default

### ReplicaSets

- also works for 1 pod and makes sure there is always one
- ReplicationController is older version of ReplicaSet

Replicas are identified using labels:

```yaml
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: myapp-replicaset
  labels:
    app: myapp
    type: front-end
spec:
  template:
  metadata:
    name: myapp-pod
    labels:
      app: myapp
      type: front-end
  spec:
    containers:
      - name: nginx-container
        image: nginx
replicas: 3
selector:
  matchLabels:
    type: front-end
```

! Labels in selector and template need to coincide, otherwise error on apply

After updating, RS will not auto-update all replicas. Either

- delete all replicas
- scale down to 0 & up again
- save manifest, delete RS and re-create

### Deployments

- rolling updates
- pause/resume rollouts
- on unexpected errors -> rollback
- uses ReplicaSet under the hood
- same manifest as ReplicaSet, just replace kind with "Deployment"

### Services

- provides single interface to applications
- connect application groups (i.e. deployments)
- make application accessible from within and outside
- behaves like a virtual server inside nodes

Service Types:

- NodePort: makes internal port accessible over port on the node
- ClusterIP: Service creates virtual IP inside cluster
  (e.g. let frontend and backend server talk to each other)
- LoadBalancer: creates LB in supported Cloud Providers

Good overview: https://kodekloud.com/blog/clusterip-nodeport-loadbalancer/#loadbalancer

#### NodePort

Used to expose service outside the cluster.
Internally builds upon ClusterIP type (see below).

CANNOT do load balancing across nodes! Load depends on the node users
explicitly connect to (though all nodes share the same service port config)

```
External Client->Node->NodePort->ClusterIP->Pod
```

- Algorithm used for load balancing: randomly
- Session Affinity: yes

3 involved ports, all described from view of the service itself

- TargetPort: port on pod where app is actually listening
  (optional, by default => Port)
- Port: port of the service (which has its own (Cluster-)IP)
  (mandatory)
- NodePort: port used to access the app externally
  (optional, choose or randomly assigned from range 30000-32767)

Example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myapp-service
spec:
  type: NodePort
  ports:
    - targetPort: 80
      port: 80
      nodePort: 30008
  selector:
    app: myapp
    type: front-end
```

#### ClusterIP

Used for pod-to-pod communication inside a cluster. Outside cannot access it.

- service gets a static IP & name to be access from inside the cluster
- load balanced across all pods

```
Pod->Pod
```

#### LoadBalancer

Used for external access, but only works on supported cloud providers with load
balancer services.

Builds upon NodePort type. Can load-balance between nodes.

```
External client -> Loadbalancer -> Worker node IP -> NodePort -> ClusterIP Service -> Pod
```

- public IP address
- will deploy e.g. a Elastic Load Balancer in AWS

### Namespaces

- `default`, `kube-system` and `kube-public` namespaces are always created
- namespaces provide resource isolation
- each NS can have own policies and quotas
- within NS resources can refer to each other simply by name, from other NS
  prepend it with scope (internal DNS name, auto-created)
  Example:
  NS "dev" internally: db-service
  from extern: db-service.dev.svc.cluster.local
- internal DNS format: service-name.namespace.object.domain

- namespace can be specified in manifest -> good practice!

-> Nice tools: kubens, kubectx

Limit resources by creating ResourceQuotas:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: dev
spec:
  hard:
    pods: "10"
    requests.cpu: "4"
    requests.memory: 5Gi
    limits.cpu: "10"
    limits.memory: 10Gi
```

### Imperative vs Declarative Commands

Imperative:

- run
- create
- expose
- edit
- scale
- set image

- create -f
- replace -f
- delete -f

! when using `edit`, definition will have `status` block and live-update specs

Declarative:

- manifests.yaml + apply
- apply can create / update / delete resources

Apply Command:

- apply can be run on entire folder of manifests
- apply will find the `right approach`

- takes 3 sources into consideration:
  - local file
  - last applied config (saved in `last-applied-configuration` annotation)
  - live config

merging strategies: https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/#how-different-types-of-fields-are-merged

## Scheduling

### Manual Scheduling

nodeName field can be used for manual scheduling. this is usually automatically
set by creating a binding object between a pods and a nodes.

when no scheduler avail., pod will go pending

manually assign with nodeName field (only at creation time):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    name: nginx
spec:
  containers:
    - name: nginx
      image: nginx
      ports:
        - containerPort: 8080
  nodeName: node02
```

for already running pods in pending mode: create binding object

```yaml
apiVersion: v1
kind: Binding
metadata:
  name: nginx
target:
  apiVersion: v1
  kind: Node
  name: node02
```

convert to json and run `curl POST` with that data against API

### Labels & Selectors

Labels are used to group things together & filter based on criteria

Set labels on pod:

```yaml
 apiVersion: v1
 kind: Pod
 metadata:
  name: simple-webapp
  labels:
    app: App1
    function: Front-end
 spec:
 ...
```

ReplicaSet uses label to identify pods:

```yaml
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: simple-webapp
  labels:
    app: App1
    function: Front-end
spec:
  replicas: 3
  selector:
    matchLabels:
      app: App1
```

Annotations: record other details like buildversion etc. for integration purposes

### Taints & Tolerations

Restrict which pods can go on which nodes

Taints:

- Taints make pods unschedulable to nodes unless they have a toleration for it

```
kubectl taint nodes <node-name> key=value:taint-effect
kubectl taint nodes node1 app=blue:NoSchedule
```

Available taint effects:

- NoSchedule
- PreferNoSchedule
- NoExecute

On master node by default a taint is set.

```
kubectl describe node kubemaster |grep Taint
```

Tolerations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
spec:
  containers:
    - name: nginx-container
      image: nginx
  tolerations:
    - key: "app"
      operator: "Equal"
      value: "blue"
      effect: "NoSchedule"
```

NOTE: Need to use double-quotes everywhere is wrong. Can also leave them out
unless special chars are used.

### Node Selectors

Let pods run only on particular nodes:

```
kubectl label nodes <node-name> <label-key>=<label-value>
kubectl label nodes node-1 size=Large
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
spec:
  containers:
    - name: data-processor
      image: data-processor
  nodeSelector:
    size: Large
```

Limitations: only a single label can be used, not sth like "small or large nodes",
or "not small nodes"

### Node (Anti-)Affinity

Like node selectors but more powerful:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
spec:
  containers:
    - name: data-processor
      image: data-processor
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: size
                operator: In
                values:
                  - Large
                  - Medium
```

currently available affinity types:

- requiredDuringSchedulingIgnoredDuringExecution -> enforce affinity-based scheduling, possibly pending
- preferredDuringSchedulingIgnoredDuringExecution -> try best, ignore if not possible

Planned:

- requiredDuringSchedulingRequiredDuringExecution -> evict pods that do not meet affinity rules

Valid operators:

- In
- NotIn
- Exists
- DoesNotExist

Taints/Tolerations vs NodeAffinity:

blue/red/green pods should only go to blue/red/green nodes, other pods should
not be scheduled onto any colored node, colored pods should not go on uncolored nodes.

- tolerations will not guarantee that pod will be scheduled only on tainted nodes
- nodeAffinity will not guarantee that other pods will not be scheduled on same nodes

--> combine both features

### Resource Management

By default can use all resources on node.
Can lead to kill of other pod.

CPU:
Minimal CPU = 1m
1 CPU = 1 AWS vCPU / 1 Azure Core / 1 Hyperthread /...

Memory:
Units: 1G, 1M, 1K, 1Gi, 1Mi, 1Ki

Requests -> Scheduling, but can use more unless...
Limit -> caps resource usage hard

If exceeding limits: CPU throttling, OOM termination

If limit is set but no requests -> requests = limit

For scheduling requests are important. Always set them!

#### Enforce Limits

Limit Ranges. Basically sets default limits. Namespace-scoped.

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: cpu-resource-constraint
spec:
  limits:
    - default: # this section defines default limits
        cpu: 500m
      defaultRequest: # this section defines default requests
        cpu: 500m
      max: # max and min define the limit range
        cpu: 1
      min:
        cpu: 100m
      type: Container
```

Does not affect existing pods, only newly schedules ones!

#### Resource Quotas

Per namespace quotas:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: disable-cross-namespace-affinity
  namespace: foo-ns
spec:
  hard:
    requests.cpu: 4
    requests.memory: 4Gi
    limits.cpu: 10
    limits.memory: 10Gi
```

### DaemonSets

ReplicaSet: ensure number of pods across different nodes are running
DaemonSet: ensure exactly one copy of pod is running on each eligible node

Examples: monitoring agent, log viewer, kube-proxy, networking solutions

Manifest similar to ReplicaSet except `kind` field.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: monitoring-daemon
  labels:
    app: nginx
spec:
  selector:
    matchLabels:
      app: monitoring-agent
  template:
    metadata:
      labels:
        app: monitoring-agent
    spec:
      containers:
        - name: monitoring-agent
          image: monitoring-agent
```

How does scheduling work?
-> From 1.12+ using NodeAffinity and default scheduler.

### Static Pods

Kubelet relies on

- instructions from kube-api
- decided by kube-scheduler
- and saved in ETCD cluster

What if none of them is available?
-> can still deploy static pods on an independend worker node!

Kubelet can only create pods. But where get info from?
-> read pod definitions from folder like `/etc/kubernetes/manifests/`

Will watch this directory and do changes as necessary when creating, updating or
deleting files there. But only works for pods, not for e.g. Deployments or
ReplicaSets. This is b/c kubelet only understands pods, nothing else.

Use `--pod-manifest-path=<path>` in kubelet conf or put it in config file (kubeadm)
field `staticPodPath`.

Investigate running static pods via docker cmd since kubectl will not be available.

Static pods will be listed by kubectl like any other pods, postfixed with nodename.

R/O mirror object is created in cluster for static pods.

Use Cases: deploy control plane components (for kubeadm)

Static Pods vs DaemonSets:

- created by kubelet vs DaemonSet controller
- deploys control plane components vs monitoring/logging agents
- both ignored by kube-scheduler

### Multiple Schedulers

- default scheduler: even distributions & considering tains & affinity
- can write own scheduler
- can have multiple schedulers

- can download binary od default scheduler and use different config
- can use kubeadm and run new scheduler as pod with custom config

- leader elect option: when running multiple copies on different nodes, only one can be active

configure pod to use custom scheduler:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
    - image: nginx
      name: nginx
  schedulerName: my-custom-scheduler
```

### Scheduler Profiles

Scheduling process:

Scheduling Queue -> Filtering -> Scoring -> Binding

Plugins:

PrioritySort -> NodeResourcesFit, NodeName, NodeUnschedulable -> NodeResourceFit, ImageLocality -> DefaultBinder

- Priority class affects sorting in queue
- nodes that cannot run the pod are filtered
- scoring weight is based on resources left after potentially scheduling pod on node (more left = better)

Can implement own plugins via "Extension Points", e.g. for filter (similar for others)

- preFilter
- filter
- postFilter

One scheduler can now have multiple profiles!

## Logging & Monitoring

### Monitor Cluster Components

- node-level metrics
- pod-level metrics
- performance metrics

Currently no built-in monitoring system.

Available options:

- metrics server (successor of heapster [deprecated]) (only in-memory)
- prometheus
- elastic stack
- datadog
- dynatrace
- ...

cAdvisor -> retrieve performance metrics from pods and expose them via kubelet to e.g. metrics server

```
kubectl top node
kubectl top pod
```

### Managing Application Logs

```
kubectl logs -f <podname> <container>
```

## Application Lifecycle Management

### Rolling Updates and Rollbacks

for deployments, new rollout creates new deployment revision

deployment strategies:

- recreate
- rolling update (default)

How rolling upgrades work:

- new ReplicaSet is created
- only few pods at a time are upgraded and "moved" to the new ReplicaSet

maxSurge (default: 25%): number of pods that can be created over the desired number during rolling update
maxUnavailable (default: 25%): number of pods that can be unavail. during rolling update

### Configuring Applications

#### Commands (Docker)

Docker does not attach terminal to container, so plain bash will immediately exit.

Dockerfile:

- CMD ["command", "param1", "param2"]
- override entire command with `docker run <image> <new_command> <args>`

- ENTRYPOINT ["command", "params"]
- override only arguments to entry point with `docker run <image> <args>`

Example:

- CMD ["sleep", "10"]
  `docker run sleeper sleep 20` -> container runs `sleep 20`
- ENTRYPOINT ["sleep"]
  `docker run sleeper 25` -> container runs `sleep 25`
- ENTRYPOINT ["sleep"] + CMD ["5"] -> set default if no cmd is given in docker cmd

#### Commands (K8s)

```docker
FROM ubuntu
ENTRYPOINT ["sleep"]
CMD ["5"]
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ubuntu-sleeper-pod
spec:
  containers:
    - name: ubuntu-sleeper
      image: ubuntu-sleeper
      command: ["sleep2.0"]
      args: ["10"]
```

- args will overwrite CMD
- command will overwrite ENTRYPOINT

#### Environment Variables

Equivalent to

```
docker run -e APP_COLOR=pink simple-webapp-color
```

in manifests:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: simple-webapp-color
spec:
  containers:
    - name: simple-webapp-color
      image: simple-webapp-color
      ports:
        - containerPort: 8080
      env:
        - name: APP_COLOR
          value: pink
```

can also load from configMaps or secrests

```yaml
env:
  - name: APP_COLOR
    valueFrom:
      configMapKeyRef:
---
env:
  - name: APP_COLOR
    valueFrom:
      secretKeyRef:
```

#### Config Maps

- used to pass configuration data in form of key-value pairs

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  APP_COLOR: blue
  APP_MODE: prod
```

Use as environment variables in pods

a) read everything from configmap

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: simple-webapp-color
spec:
  containers:
    - name: simple-webapp-color
      image: simple-webapp-color
      ports:
        - containerPort: 8080
      envFrom:
        # !! list here !!
        - configMapRef:
            name: app-config
```

b) read single value from configmap

```yaml
env:
  - name: APP_COLOR
    valueFrom:
      configMapKeyRef:
        name: app-config
        key: APP_COLOR
```

c) mount as volume/file

```yaml
volumes:
  - name: app-config-volume
    configMap:
      name: app-config
```

#### Secrets

Do not use configMaps for secret data. Instead use secrets.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
data:
  DB_Host: bX1zcWw=
  DB_User: cm9vdA==
  DB_Password: cGFzd3Jk
```

Proper encoding when using `data`:

```
echo -n "secret-string" | base64
echo -n "c2VjcmV0LXN0cmluZw==" | base64 -d
```

Can also use `stringData` with unencoded secret strings.

Rest similar to configmaps, just use instead of `configMapRef` use `secretRef` etc.

a) read everything from secret

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: simple-webapp-color
spec:
  containers:
    - name: simple-webapp-color
      image: simple-webapp-color
      ports:
        - containerPort: 8080
      envFrom:
        # !! list here !!
        - secretRef:
            name: app-secret
```

b) read single value from configmap

```yaml
env:
  - name: APP_COLOR
    valueFrom:
      secretKeyRef:
        name: app-secret
        key: APP_COLOR
```

c) mount as volume/file

```yaml
volumes:
  - name: app-config-volume
    secret:
      secretName: app-secret
```

!! NOTE !!

- Secrets are not encrypted, only encoded. Everyone with cluster access can read secret data. Don't push secret manifests to git.
- This means, secrets are not encrypted in ETCD (see above)
- Possibility to encrypt secret data at rest using `EncryptionConfiguration` (only applies to new secrets)
- Can configure least-privilege access via RBAC
- Consider 3rd party secret store providers such as AWS, Azure, GCP, Vault,..

--> Secrets in K8s are in fact not really "secure" as long as you don't use sth. like Sops/HelmSecrets or
SealedSecrets, because they live unencrypted in the cluster and (hopefully not) in git

- secret is only sent to node if required
- kubelet stores secret in tmpfs, doesn't write it to disk
- when pod which required the secret is deleted, local copy of secret is deleted as well

#### Multicontainer Pods

- microservices vs monolithic apps
- e.g. log agent, web server
- share same life-cycle, network space and storage volumes

-> no need to take care of networking and shared storage manually

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: simple-webapp
  labels:
    name: simple-webapp
spec:
  containers:
    - name: simple-webapp
      image: simple-webapp
      ports:
        - ContainerPort: 8080
    - name: log-agent
      image: log-agent
```

Common design patterns (see CKAD course):

- sidecar
- adapter
- ambassador

Init Containers:

- used to e.g. pull code/binary from repo for use in main app,
  wait for external service/DB before app start
- run to completion before other containers start
- `initContainers` section instead of `containers`
- run one at a time in sequential order
- if any fail, pod is restarted repeatedly until all init containers succeed

Health Checks (see CKAD course):

- readiness probe
- liveness probe
- startup probe

## Cluster Maintenance

### OS Upgrades

- impacts with apps running on only a single replica / pod
- downtimes of at least the pod eviction time-out (default: 5m -> kube-controller-manager)
  (time before node is considered dead)

-> during maintenance don't just take down nodes.

- drain nodes purposfully
- pods get recreated on different node
- node is cordoned so no other pods can be scheduled on it
- respects PDBs

### Versions

- vMajor.Minor.Patch
- minor release every few months, first stable in Mar 2015
- alpha (feature) -> beta (testing) -> stable

- all core-components of the control plane share the same version:
  - kube-apiserver
  - controller-manager
  - kube-scheduler
  - kubelet
  - kube-proxy
  - kubectl
- other components that are separate projects have different versioning
  - ETCD cluster
  - CoreDNS

### Upgrading

- all component talk to API server, so no component should ever have higher
  version than kube-apiserver
- controller-manager and kube-scheduler can be up to 1 version lower
- kubelet and kube-proxy can be up to 2 versions lower
- kubectl can be +/- 1 of what kube-apiserver is

Cloud Provider -> just click upgrad
kubeadm -> `kubeadm upgrade plan/apply`
hard way -> manual fun

2 major steps during upgrade:

- upgrade master nodes
  - apiserver, scheduler and controller-manager go down briefly
  - does not automatically mean worker nodes and pods are affected
  - all workload hosted on worker nodes continue serving
  - only management functions are down, like `kubectl` or API calls or deploy/modify stuff
  - will end in supported configuration: master version = worker version + 1
- upgrade worker nodes
  - strategy 1: all at once -> all pods go down -> DOWNTIME!
  - strategy 2: one node at a time -> constantly re-create pods
  - strategy 3: add new nodes with newer version (esp. useful in cloud environments)

Kubeadm will upgrade core components except kubelets. Kubeadm must be upgraded
to next higher minor version as well and follows same versioning as core components.

Kubelet does not necessarily have to be deployed on the control plane!

### Backup and Restore Methods

Options:

- put resource configs to github (potentially miss imperatively created objects)
- query kubeapi server (includes everything that is currently running in cluster)

  ```
  kubectl get all -A -o yaml > everything.yaml
  ```

- use tools like Velero (basically does api server approach)
- backup ETCD server

NOTE: cool dudes use k8up nowadays ;-) - https://k8up.io/k8up

ETCD:

- supports restoring from same major.minor version
- backup path via etcd.service -> `--data-dir=<path-to-backup>` or in pod config
- can do snapshots with `etcdctl snapshot save snap.db`

NOTE: mind version of `etcdctl -v / version` (API v2/v3) vs. version of `etcd` itself (check pod image)

## Security

### Security Primitives

Hosts:

- PW-based auth disabled
- use SSH-key based auth instead

kube-apiserver:

important b/c you can do almost any operation on the cluster with direct API
calls or via kubectl that also talks to the api-server via API calls.

- who can access?
  - files: username + pw
  - files: username + token
  - certificates
  - external auth providers e.g. via LDAP
  - service accounts
- what can they do?
  - RBAC authorization
  - ABAC authorization
  - node authorization
  - webhook mode

Communication between api server and other components like ETCD cluster,
kubelets, scheduler, proxies, controller manager etc. are secured via TLS
encryption

By default all pods can access all other pods in the cluster.
Use network policies to prevent that.

### Basic Authentication (not recommended)

NOTE: This has been deprecated in K8s v1.19 !!

Different users accessing the cluster

- admins
- developers
- application end users (handled by apps, so not considered here)
- bots

-> users vs service accounts

K8s does not manage users internally but relies on external sources, except for
service accounts. So there is no

```
kubectl create user <username>
kubectl list users
```

but only a

```
kubectl create serviceaccount sa1
kubectl get serviceaccount
```

All requests go through kube-apiserver and authenticates before processing!

- static pw/token files -> `user-details.csv` with pw,username,userid,groupname[optional]

  ```
  password123,user1,u0001[,group1]
  password123,user2,u0002[,group1]
  password123,user3,u0003[,group2]
  ```

  can be passed to api server via `--basic-auth-file=<filename>`

  Used in `curl` with `curl ... -u "user:pw"`

- similar with token file by replacing pw column with tokens, passed to api server
  via `--token-auth-file=<filename>` and in `curl` as `--header "Authorization: Bearer <token>"`

-> not recommended! consider volume mount while providing auth files in kubeadm setup.

Also need to setup RBAC rules for new users.

-> Better use certificate-based authentication!

### TLS Basics

NOTE: mostly skipped

Public Key Infrastructure (PKI)

- browser's symmetric secret shared via asymmetric key exchange with server
- intranets often use commercial CAs like Symantec, digicert, GlobalSign etc.

different keys in use:

- key pair for SSH
- key pair for server certificate
- key pair for CA certificate / signing server certs
- symmetric key for end user / browser
- also client certificates possible so server can validate if client is who it says it is

Naming conventions:

- certificate (=pub key): .crt, .pem
- private key: .key, -key.pem

### TLS in Kubernetes

What to encrypt?

- communication between control plane and worker nodes
- communication between users and kube-apiserver

Server Certificates:

- kube-apiserver: apiserver.crt, apiserver.key
- ETCD cluster: etcdserver.crt, etcdserver.key
- kubelets: kubelet.crt, kubelet.key

Client Certificates:

- users (via kubectl or REST calls): admin.crt, admin.key
- kube-scheduler: scheduler.crt, scheduler.key
- kube-controller-manager: controller-manager.crt, controller-manager.key
- kube-proxy: kube-proxy.cert, kube-proxy.key

-> some components are from api-server's POV just another client

Remember: apiserver is the only component that talks to the ETCD cluster
directly. either using the server certs or create a dedicated key pair (=client
certificate from ETCD's/kubelets POV) for it.

Same goes for kubelets.

Optional client certificates:

- apiserver to etcd: apiserver-etcd-client.crt, apiserver-etcd-client.key
- apiserver to kubelet: kubelet-client.crt, kubelet-client.key

Certificate Authority:

- Kubernetes requires at least 1 CA, but can have multiple
- ca.crt, ca.key

### TLS Certificates

Tools available:

- easyrsa
- openssl (preferred one)
- cfssl

CA is created self-signed, server and client certificates are then signed by
this CA:

- usage in curl REST calls: `curl <URL> --key admin.key --cert admin.crt --cacert ca.crt`
- For `kubectl` this configuration goes into `kube-config.yaml` file.
- needs to be deployed to all hosts!

```
openssl genrsa -out ca.key 2048
openssl req -new -key ca.key -subj "/CN=KUBERNETES-CA" -out ca.csr
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt
```

Generate admin user certificate. `system:masters` group is mandatory here.

```
openssl genrsa -out admin.key 2048
openssl req -new -key ca.key -subj "/CN=kube-admin/O=system:masters" -out admin.csr
openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -out admin.crt
```

Similar for all other components like kube-scheduler etc., although their name
must be prefixed with "system" like so: "SYSTEM:KUBE-SCHEDULER"

Specifically to kube-apiserver server cert are following aliases:

- kubernetes
- kubernetes.default
- kubernetes.default.svc
- kubernetes.default.svc.cluster.local
- <IP>

Use openssl config file:

```
[req]
req_extension = v3_req
distinguished_name = req_distinguished_name

[v3_req]
basicContraints = CA:FALSE
keyUsage = nonRepudiation,
subjectAltName = @alt_names

[alt_names]
DNS.1 = kubernetes
DNS.2 = kubernetes.default
DNS.3 = kubernetes.default.svc
DNS.4 = kubernetes.default.svc.cluster.local
DNS.5 = 10.96.0.1
DNS.6 = 172.17.0.87
```

```
openssl req -new -key apiserver.key -subj "/CN=kube-apiservera" -out apiserver.csr -config <config-file>
```

For kubelet certs, we need to use "system:node:<nodename>" and group "SYSTEM:NODES"

### Viewing Certificates

Find certificate paths:

- manual: `/etc/systemd/system/kube-apiserver.service`
- kubeadm: `/etc/kubernetes/manifests/kube-apiserver.yaml`

Check logs for debugging:

- manual: `journalctl -u etcd.service -l`
- kubeadm: `kubectl logs -n kube-system etcd-master` or if apiserver is down `docker logs ..`

### Certificates API

Since CA is signing everything incl. user certificates, it needs to be protected.
Place it on a secure server. `kubeadm` places it on the control plane node.

We don't have to manually ssh there and run openssl commands, instead use
kubernetes built-in certificates API (provided by controller-manager)

User locally:

```
openssl genrsa -out jane.key 2048
openssl req -new -key jane.key -subj "/CN=jane" -out jane.csr
```

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: jane
spec:
  groups:
    - system:authenticated
  usages:
    - digital signature
    - key encipherment
    - server auth
  request: <certificate-goes-here>
```

CSR in field needs to be base64-encoded and free of new-lines!

```
cat jane.csr | base64 | tr -d "\n"
```

Approve/reject CSR:

```
kubectl get csr
kubectl certificate approve jane
kubectl certificate deny jane
```

Extract certificate:

```
kubectl get csr jane -o yaml

# copy status.certificate block

echo "<block content>" | base64 -d
```

### Kubeconfigs

Authentication for manual calls against REST API:

```
curl https://<URL>:6443/api/v1/pods \
--key admin.key --cert admin.cert --cacert ca.crt
```

With `kubectl`:

```
kubectl get pods \
--server <URL>:6443 \
--client-key admin.key \
--client-certificate admin.crt \
--certificate-authority ca.crt
```

Tedious, so put in a config file with 3 main sections:

- Clusters -> e.g. dev/prod
- Users -> user accounts with which you have access to clusters, e.g. admin
- Contexts -> which user account is used for which cluster, e.g. admin@prod

```
kubectl get pods --kubeconfig config
```

Real-life kubeconfig example for minikube cluster:

```yaml
apiVersion: v1
kind: Config
current-context: minikube
clusters:
  - name: minikube
    cluster:
      certificate-authority: /home/rene/.minikube/ca.crt
      server: https://192.168.49.2:8443
users:
  - name: minikube
    user:
      client-certificate: /home/rene/.minikube/profiles/minikube/client.crt
      client-key: /home/rene/.minikube/profiles/minikube/client.key
contexts:
  - name: minikube
    context:
      cluster: minikube
      namespace: default
      user: minikube
```

Especially note the following keys:

- default context: current-context
- default namespace: contexts.context.namespace

Can also specify certificates directly as base64-encoded string by using
`certificate-authority-data` instead of `certificate-authority`.

### API Groups

Kubernetes API

- /metrics
- /healthz
- /version
- /api
- /apis
- /logs -> e.g. 3rd party logging

Core group /api/v1

- /namespaces
- /pods
- /nodes
- /secrets
- etc...

Named group /apis

- /apps/v1
  - /deployments
  - /replicasets
  - /statefulsets
    - verbs: list, get, create, delete, update, watch
- /extensions
- /networking.k8s.io
- /storage.k8s.io
- /authentication.k8s.io
- /certificates.k8s.io
- etc...

Generally: Core / Named API Group -> Section Group -> Optional: Version -> Resources -> Verbs

List APIs locally:

- curl + full list of certs
- `kubectl proxy` + `curl -k localhost:8001`

!! NOTE:

- kube proxy: enable connectivity between different pods & nodes across the cluster
- kubectl proxy: http proxy service to access kube-api server

### Authorization

Authorization helps to control who can do what in the cluster.

Different authorization mechanisms are available:

- Node Authorization
- Attribute-based Authorization (ABAC)
- Role-Based Authorization (RBAC)
- Webhook

Node Authorization (cluster-internal):

- Users access kube API like kubeletes
- kubelets read services, nodes, pods etc. and writes to node status, pod status etc.
- permissions are handled by "node authorizer"
- permissions checked & granted via node certificates that are part of
  "SYSTEM:NODES" and prefixed with "system:node:<nodename>"

ABAC (Attribute-based authorization control):

- policy definition file with entries for each user
- difficult to manage since file needs to be adapted manually and kubeapi
  server always needs to be restarted for changes to take effect

https://kubernetes.io/docs/reference/access-authn-authz/abac/

```
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user": "alice", "namespace": "*", "resource": "*", "apiGroup": "*"}}
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user": "kubelet", "namespace": "*", "resource": "events"}}
{"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user": "bob", "namespace": "projectCaribou", "resource": "pods", "readonly": true}}
```

RBAC (Role-based access control):

- create roles with a set of permissions and associate users to them
- changes to roles take effect immediately
- more standardized approach to access control

Webhook:

- for external tools like "Open Policy Agent"

AlwaysAllow/AlwaysDeny:

- pretty self-explaining ;-)
- AlwaysAllow is configured by default of none other is specified

Multiple different mechanisms can be used together and take precedence in the
order they are passed to the API server:

```
ExecStart=/usr/loca/lbin/kube-apiserver \
...
--authorization-mode=Node,RBAC,Webhook \
...
```

As long as modules deny requests the next module is asked.

### RBAC

Each role has 3 sections

- apiGroups
- resources
- verbs
- resourceNames (optional, restrict to individual objects of a resource)

Define roles

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
rules:
  - apiGroups: [""] # "" indicates the core API group
    resources: ["pods"]
    verbs: ["get", "list", "update", "delete", "create"]
  - apiGroups: [""]
    resources: ["ConfigMap"]
    verbs: ["create"]
```

common verbs:

- get
- list
- watch
- create
- update
- patch
- delete
- bind

Link user to the role via RoleBinding

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: devuser-developer-binding
subjects:
  - kind: User
    name: dev-user # "name" is case sensitive
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
```

possible subjects:

- User
- Group
- ServiceAccount

-> Roles and RoleBindings are namespace-scoped objects!

### Cluster Roles and RoleBindings

Most resources are namespace specific, like pods, deployments etc.
Nodes for instance cannot be associated to a particular namespace.

Difference between either "namespaced" or "cluster-scoped"!

Examples:

- nodes
- clusterrole
- clusterrolebinding
- PV (but not PVC!)
- CSR
- namespaces

Full list:

```
kubectl api-resources --namespaced=true|false
```

Why use clusterroles? -> Adapt cluster-wide resources like

- create/delete nodes
- create/delete PVs

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-administrator
rules:
  - apiGroups: [""] # "" indicates the core API group
    resources: ["nodes"]
    verbs: ["get", "list", "delete", "create"]
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-role-binding
subjects:
  - kind: User
    name: cluster-admin
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-administrator
  apiGroup: rbac.authorization.k8s.io
```

Usage is not restricted to above. Can also create a ClusterRole for namespaced
resources as well. Users then have access to resources across the entire cluster.

Default cluster roles are usually prefixed with `system:` and labeled with
`kubernetes.io/bootstrapping=rbac-defaults`.

Check for more info: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings

Additional field in policy rules (kubectl describe output) compared to roles:
NonResourceURLs -> e.g. /healthz

### Service Accounts

Used by an application like Jenkins or Prometheus (instead of real user).

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: build-robot
  automountServiceAccountToken: false
```

(NOTE: serviceAccount is deprected, use serviceAccountName instead!)

On creation, also a corresponding token is created that needs to be used by the
external application to access the kube API.

Tokens are stored as k8s secrets. Used in REST calls e.g. via curl as
authorization bearer token.

In case 3rd party application is hosted on the same k8s as well, there's no
need to extract the token. Simply mount service token secret as volume into
application.

Default SA for every namespace & automatically mounted to each pod in each NS
to `/var/run/secrets/kubernetes.io/serviceaccount` as 3 separate files:

- ca.cert
- namespace
- token -> actual token

Only permissions for basic API requests.

Prevent with

```
spec.automountServiceAccountToken = false
```

!! Changes as of v 1.22 / 1.24 !!

Decode token either using https://jwt.io or using

```
jq -R 'split(".") | select(length > 0) | .[0],.[1] | @base64d | fromjson' <<< <TOKEN>
```

NEW in 1.22: TokenRequestAPI (KEP 1205)

Old implementation was not audience or time bound, hence did not contain
an expiration date. Tokens were valid as long as the SA exists! Also one secret
per service account.

-> security and scalability issues

now:

- audience bound
- time bound
- object bound

Pods now do not rely anymore on the SA token secret, but instead a token with
defined life time is created by SA admission controller and mounted as
projected volume (https://kubernetes.io/docs/concepts/storage/projected-volumes/)

NEW in 1.24: Reduction of secret-based SA tokens (KEP-2799)

Before: on SA creation also token is created as k8s secret and auto-mounted
into pods using this SA.

Now: no auto-created token, need to do it manually

```
kubectl create token <SA-name>
```

Token will now have an expiry date of 1h by default.

Still possible to create token-secrets the old way using

```yaml
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: mysecretname
  annotations:
    kubernetes.io/service-account.name: <SA-name>
```

Read more: https://kubernetes.io/docs/concepts/configuration/secret/#service-account-token-secrets

### Image Security

Follow Docker image naming convention:

- image: nginx # is equal to
- image: library/nginx # is equal to
- image: docker.io/library/nginx

general pattern: image: <registry>/<account>/<image>

- library is Docker's default user account
- docker.io is Docker's default registry

other important registries:

- google: gcr.io

Private Registries:

for docker:

```
docker login private-registry.io
docker run private-registry.io/apps/internal-app
```

in kubernetes:

```
 kubectl create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=registry-user \
  --docker-password=registry-password \
  --docker-email=registry-user@org.com
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
    - name: nginx
      image: private-registry.io/apps/internal-app
  imagePullSecrets:
    - name: regcred
```

### Container Security

Process isolation:

- host runs processes like ssh-server, services, docker daemon etc.
- containers & host not completely separated - they share the same kernel
- containers are isolated using linux namespaces
  -> container processes can only see other processes in same namespace
- container process has PID 1 in container, but e.g. 3816 on host

Users:

- Docker host has set of users: root + others
- by default docker runs processes in containers as root
- override using `USER 1000` in Dockerfile or via `docker run --user=1000`
- abilities of root user within container are limited by docker
- container-root != host-root

Linux Capabilities:

CHOW, DAC, KILL, SETFCAP, SETPCAP, SETGID, SETUID, NET_BIND, NET_RAW, BROADCAST, SYS_CHROOT etc...
(full list check: /usr/include/linux/capability.h)

- by default docker runs containers with limited privileges
- e.g. cannot reboot host or control other containers

adapt with `docker run ...`

- `--cap-add MAC_ADMIN`
- `--cap-drop KILL`
- `privileged` -> enables all privileges

Security Contexts:

Implementation in k8s on pod level...

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  securityContext:
    runAsUser: 1000
  containers:
    - name: ubuntu
      image: ubuntu
      command: ["sleep", "3600"]
```

or container level

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  containers:
    - name: ubuntu
      image: ubuntu
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 1000
```

Container takes precedence over pod config!

Capabilities are only supported at container level, not pod level:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  containers:
    - name: ubuntu
      image: ubuntu
      command: ["sleep", "3600"]
      securityContext:
        runAsUser: 1000
        capabilities:
          add: ["MAC_ADMIN"]
```

### Network Policies

- Always from of a specific component's perspective
- Ingress: incoming traffic
- Egress: outgoing traffic

- Nodes hosting pods and services, each having their own IP address
- They should be able to communicate w/o creating routes!

By default: "All Allow"

NetworkPolicy:

- linked to one or many pods via labels & selectors
- important is only the originating direction (reply automatically allowed)
- define network rules within (e.g. allow ingress from podA on port 3306)

NOTE: ingress/egress isolations only comes into effect if ingress/egress is
set under `spec.policyTypes`! If one is missing, all corresponding traffic is
NOT blocked.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-policy
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: api-pod
      ports:
        - protocol: TCP
          port: 3306
```

Can also use multiple selectors combined, e.g. podSelector & namespaceSelector
to only allow a pod named "podname" from a specific namespace to connect
(imagine you have DEV/TEST/PROD namespaces, all containing a pod "api-pod", but
only the one from PROD should be able to connect to the PROD database).

- podSelector
- namespaceSelector
- ipBlock (e.g. for external servers)

Each `spec.ingress.from[]` / `spec.egress.to[]` item can have multiple
selectors that work as OR operations.

```yaml
spec:
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: api-pod
          namespaceSelector:
            matchLabels:
              name: prod
        - ipBlock:
            cidr: 192.168.5.10/32
```

Instead of `matchLabel` can also use `matchExpressions`:

```yaml
spec:
  egress:
    - to:
        - namespaceSelector:
            matchExpressions:
              - key: namespace
                operator: In
                values: ["frontend", "backend"]
```

Not all K8s network solutions support networkPolicies:

| Support        | No Support |
| -------------- | ---------- |
| kube-router    | flannel    |
| calico         |            |
| romana         |            |
| weave-net (\*) |            |

\* discontinued

Can still create networkPolicies, but they just will be ignored.

As of Kubernetes 1.27 not possible:

- anything TLS related
- targeting of services by name
- targeting of services by name
- log network security events
- prevent loopback or incoming host traffic
- explicitly deny policies

## Storage

### Storage in Docker

Default location: `/var/lib/docker/` with subfolders

- aufs
- container
- image
- volumes

Layered (image) architecture:

- each line in Dockerfile creates new layer in image
- re-using cached layers on new builds
- final image layers are read-only

When running container:

- new writable "container" layer is created
- hold log files, or just anything created during runtime
- lives only as long as container is alive
- unique to running instance
- copy-on-write mechanism: image layer files can be edited, but diff is stored
  in container layer, not image layer (surprise...surprise :D)

If changes need to be saved long-term, use persistent volumes:

```
# use explicit volume (volume-mounting, /var/lib/docker/volumes/myvol)
docker volume create myvol
docker run -v myvol:/var/lib/mysql mysql

# mount directory directly (bind-mount)
docker run -v /absolute/path:/container/path <image>
```

NOTE: `-v` is old-style, new-style is using `--mount` option:

```
docker run --mount type=bind,source=/data/mysql,target=/var/lib/mysql mysql
```

Common storage drivers:

- AUFS
- ZFS
- BTRFS
- Device Mapper
- Overlay
- Overlay2

Volumes handled by volume driver plugins, not storage drivers!

- local (default)
- Azure File Storage
- Convoy
- DigitalOcean Block Storage
- Flocker
- gce-docker
- GlusterFS
- NetApp
- RexRay
- Portworx
- VMware sSphere Storage

```
docker run --name mysql --volume-driver rexray/ebs --mount src=ebs-vol,target=/var/lib/mysql mysql
```

### Container Storage Interface (CSI)

CRI (container runtime interface):
standard defining how orchestrators like k8s communicate with rkt, cri-o or docker

CNI (container network interface):
standard defining how k8s talk to networking solutions like weaveworks, flannel, cilium

CSI (container storage interface):
standard for storage solutions in k8s

CSI:

- is not a K8s-specific standard, but instead meant to be a universal one and
  currently used at least by k8s, cloud foundry and mesos.
- defines set of RPCs to be called by orchestrator and implemented in the
  storage driver

### (Plain) Volumes

Attach volume to container to persist data:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: random-number-generator
spec:
  containers:
    - image: alpine
      name: alpine
      command: ["/bin/sh", "-c"]
      args: ["shuf -i 0-100 -n 1 >> /opt/number.out;"]
      volumeMounts:
        - mountPath: /opt
          name: data-volume
  volumes:
    - name: data-volume
      hostPath:
        path: /data
        type: Directory
```

- Directory type will map node directory to pod
- not recommended for multi-node setups ...obviously...

Supported storage solutions:

- NFS
- GlusterFS
- Flocker
- ceph
- scaleIO
- Cloud, AWS / Azure / GPCA

Example:

```yaml
volumes:
  - name: data-volume
    awsElasticBlockStore:
      volumeID: <volume-id>
      fsType: ext4
```

### Persistent Volumes

Before: all volume config goes into pod definition file -> hard to do changes.

Better: manage storage centrally

Persistent Volume:

- cluster wide pool of volumes
- configured by cluster admin
- users can access them for applications via PVCs

```yaml
kind: PersistentVolume
apiVersion: v1
metadata:
  name: pv-vol1
spec:
  accessModes: ["ReadWriteOnce"]
  capacity:
    storage: 1Gi
  hostPath:
    path: /tmp/data
```

(NOTE: again here, don't use hostPath in production clusters! It's just for simplicity and demoing.)

Access Modes:

- ReaOnlyMany
- ReadWriteOnce
- ReadWriteMany

### PersistentVolumeClaims

Admin: create set of PVs
User: create PVCs in order to use/access PVs
K8s: binds volumes to claims depending on exact properties

- every PVC is bound to a single PV
- k8s tries to find a PV with sufficient capacity as requested by the claim
  and that provides requested properties such as access mode etc.
- for multiple possible matches still can use labels & selectors
- smaller claims may get bound to larger volume when there are no better
  fitting options
- when there are no available PVs, PVC will stuck in "pending" state

```yaml
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: myclaim
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 1Gi
```

What happens when Claim is deleted? (`PersistentVolumeReclaimPolicy`)

- Retain (default): not avail. for reuse by other claims, manual reclamation
- Delete: volume is deleted
- Recycle: basic scrub (`rm -rf <volume>`)

When deleting a PVC while used by a pod, PVC will hang in "terminating" state.

Contrary, if there is no pod yet consuming the PVC, it depends on the setting

```
volumeBindingMode = Immediate # (default)
volumeBindingMode = WaitForFirstConsumer
```

See https://kubernetes.io/docs/concepts/storage/storage-classes/#volume-binding-mode

### App configuration

Replace `hostPath` block in pod definition by PVC:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: random-number-generator
spec:
  containers:
    - image: alpine
      name: alpine
      command: ["/bin/sh", "-c"]
      args: ["shuf -i 0-100 -n 1 >> /opt/number.out;"]
      volumeMounts:
        - mountPath: /opt
          name: data-volume
  volumes:
    - name: data-volume
      persistentVolumeClaim:
        claimName: myclaim
```

NOTE: Statefulsets out-of-scope for CKA. See CKAD.

### Storage Classes

Static Provisioning:

Every time we want to use a persistent disk like EBS, GCE persistent disk or
Azure disk, this volume needs to be created manually on cloud-side.

Dynamic Provisioning via Storage Classes

- Define a provisioner (like google storage)

  ```yaml
  apiVersion: storage.k8s.io/v1
  kind: StorageClass
  metadata:
    name: google-storage
  provisioner: kubernetes.io/gce-pd
  ```

- don't need PV definition anymore since it is created automatically by
  storage class
- set storage class in PVC

  ```
  kind: PersistentVolumeClaim
  apiVersion: v1
  metadata:
    name: myclaim
  spec:
    accessModes: [ "ReadWriteOnce" ]
    storageClassName: google-storage
    resources:
    requests:
      storage: 500Mi
  ```

## Networking

### Routing

Route basics:

- interfaces on host `ip link`
- connect to switch for network access
- multiple networks linked via router (has an IP in each network)
- show kernel routing table with `route`
- internet gateway usually default one (equal to 0.0.0.0)

Example for ping from A to C via B: A--B--C

- to networks 192.168.1.0/24 and 192.168.2.0/24, B has an IP in both
- without routes `ping` gives "Connect: Network is unreachable"
- after adding routes, error is gone but still no proper response

-> By default, linux does not simply forwards packages from one interface to
another for security reasons! Need to enable explicitly.

### DNS

Manual entries in `/etc/hosts`

```
192.168.1.11  server-name
```

No checks here! Can also re-assign e.g. `google.com`

Better way via DNS server `cat /etc/resolv.conf`

```
nameserver <IP>
```

Order defined in `/etc/nsswitch.conf`

```
hosts: files dns
```

www.website.com

| part            | name                   |
| --------------- | ---------------------- |
| .com            | top level domain (TLD) |
| website.com     | root / domain apex     |
| www.website.com | subdomain              |

(wrongly explained in video!)

Resolve hosts on internal network simply by "first name" (=hostname) instead of
hostname.domain.tld - put in `/etc/resolv.conf`

```
search domain.tld sub1.domain.tld sub2.domain.tld
```

Important DNS record types

| name  | from   | to     |
| ----- | ------ | ------ |
| A     | domain | IPv4   |
| AAAA  | domain | IPv6   |
| CNAME | domain | domain |

### Installing CoreDNS

Fetch and extract tarball

```
wget https://github.com/coredns/coredns/releases/download/v1.7.0/coredns_1.7.0_linux_amd64.tgz
tar -xzvf coredns_1.7.0_linux_amd64.tgz
```

Configure the `/etc/hosts` file, CoreDNS will pick the ips and names from it.

```
192.168.1.10 web
192.168.1.11 db
192.168.1.15 web-1
192.168.1.16 db-1
192.168.1.21 web-2
192.168.1.22 db-2
```

Adding into the Corefile

```
. {
hosts /etc/hosts
}
```

Run the executable file (listens on port 53 by default)

```
./coredns
```

### Network Namespaces

Reminder:

- container only sees its own processes
- host can see all processes, its own and all started from within containers
- PIDs will differ between host and containers

Networking:

- network isolation on Docker
- container has its own network namespace with dedicated virtual interfaces,
  routing and ARP tables

Linking:

- two can be linked via virtual ethernet pair
- multiple can be linked through virtual switch -> Linux Bridge, Open vSwitch
  (this bridge is an interface on the host!)

Check cheat sheet for all commands!

### Docker Networking

None:

```
docker run --network none nginx
```

- no network is connected, no one can reach the container from outside and vice-versa

Host:

```
docker run --network host nginx
```

- container is attached to host network, i.e. no network isolation
- e.g. expose web app in container on port 80, then it's reachable on this
  port on the host

Bridge:

```
docker run --network bridge nginx
```

- internal private network is created to which containers and host are attached
- on host: `docker-0` via `ip link`, in docker `bridge` (check with `docker network ls`)
- pair of interfaces is created for each container
- can identify pairs of interfaces by name, e.g. eth0@if12 (container) is
  connected to veth68fbef0@if11, same for ..if8 and ..if7
- outside access via port mapping on host using iptables rules

### Container Networking Interface (CNI)

- basic principle given by network namespaces
- docker basically follows the same concept only with different naming patterns
- other container solutions solve it the same way (e.g. rkt, mesos, k8s)

All trying to solve the same thing with the same concepts.

- refactor solution into a programm ("plugin") so that container runtimes only
  need to pass container ID
- defines set of responsibilities for runtimes and plugins
- every runtime should be able to work with any plugin

default plugins:

- bridge, vlan, ipvlan, macvlan, windows ; HDCP, host-local

3rd party plugins:

- weaveworks (discontinued)
- flannel
- cilium
- vmware NSX
- calico
- infoblox

NOTE: docker DOES NOT implement CNI, but has it's own set of standards "CNM",
container network model.

### Cluster Networking

- each node must have at least 1 interface connected to a network
- each interace must have an IP address configured
- hosts must have a unique hostname & MAC address
- required open ports:
  - master nodes:
    - 6443 : api-server
    - 2379 : etcd server
    - 2380 : etcd clients (if clustered)
    - 10250 : kubelet (optional)
    - 10251 : scheduler
    - 10252 : controller manager
  - worker nodes:
    - 10250 : kubelet
    - 30000 - 32767 : services

NOTE: above list seems outdated. check here for up-to-date list:
https://kubernetes.io/docs/reference/networking/ports-and-protocols/

### Pod Networking

So far: node networking

Networking on pod layer?

- how are pods addressed
- how do they communicate with each other
- how access service running on pods internall and externally

No built-in solution! Only requirements are defined:

- every pod should receive an IP address
- every pod should reach every other pod on the same node using this IP
- every pod should reach every other pod on other nodes using this IP (w/o NAT)

### CNI in Kubernetes

Container Runtime responsibilities:

- create network namespace
- identify network container must attach to
- invoke Network Plugin (bridge) when container is added (ADD)
- invoke Network Plugin (bridge) when container is deleted (DEL)
- JSON format of network configuration

Configuring CNI:

kubelet.service / `ps -aux | grep kubelet`

```
ExecStart=/usr/loca/bin/kubelet ...
  --network-plugin=cni \\
  --cni-bin-dir=/opt/cni/bin \\
  --cni-conf-dir=/etc/cni/net.d \\
```

### Example: Weave Works

NOTE: This CNI is discontinued! For conceptional understanding still sufficient ;-).

- deploys service/agent on each node (daemonset) to intercept traffic and take over routing
- each agent stores topology of entire cluster (hosts & IPs)
- weave makes sure that pod get correct route configured to reach the agents,
  then agents take over the rest (by encapsultion)

### IPAM

How are IPs assigned, who is responsible?

- CNI states: responsibility is on CNI plugin side
- interally uses either host-local or DHCP

### Service Networking

Recap:

- services get their own IP
- services are accessible from all nodes, not bound to specific node
- services are cluster-wide objects, in fact they don't exist at all, there's
  no processes listening on this IP, it's just a virtual object
- IP is taken from predefined range, passed to kube-proxy which in turn creates
  fitting forwarding rules to the underlying pods
- types: ClusterIP, NodePort, LoadBalancer

Service IP range:

- default: 10.0.0.0/24
- defined by kube-api-server setting `--service-cluster-ip-range=<CIDR>`

NOTE: Pod and Service IP ranges may not overlap!!

Proxy modes:

- userspace
- ipvs
- iptables (default)

All iptable rules for a specific service have a corresponding comment

```
iptables -L -t nat | grep <service-name>

KUBE-MARK-MASQ  all  --  10.244.1.3     anywhere        /* default/local-cluster: */
DNAT            tcp  --  anywhere       anywhere        /* default/local-cluster: */            tcp to:10.244.1.3:80
KUBE-MARK-MASQ  tcp  -- !10.244.0.0/16  10.101.67.139   /* default/local-cluster: cluster IP */ tcp dpt:http

KUBE-SVC-SDGXHD6P3SINP7QJ  tcp  --  anywhere  10.101.67.139  /* default/local-cluster: cluster IP */ tcp dpt:http
KUBE-SEP-GEKJR4UBUI5ONAYW  all  --  anywhere  anywhere       /* default/local-cluster: */
```

### DNS in Kubernetes

Node hostnames and DNS records are managed within company or cloud provider,
so exclusively focus on pods and services here!

DNS within cluster:

- for each service a DNS record is created that maps service name to IP
- FQDN: <service>.<namespace>.svc.cluster.local
- Records for PODS are not created for pods, but can be enabled
- pod DNS records use IP address with dashes instead of dots as hostname,
  i.e. <IP>.<namespace>.pod.cluster.local

CoreDNS:

- prior to v1.12 -> kube-dns
- for v1.12+ -> CoreDNS
- deployed as pod (deployment in fact)
- requires config file: /etc/coredns/CoreFile -> configure plugins
- pods point to kube-dns service created by CoreDNS as DNS server,
  check `/etc/resolv.conf` -> configured in kubelet
- adds default search entries for services so these parts can be ommited
  - cluster.local
  - svc.cluster.local
  - default.svc.cluster.local

### Ingress

On-prem:

- create application accessing DB on pod via ClusterIP service type
- users can access app via other service of type NodePort via http://<node-ip>:38080
- service + deployment takes care of load-balancing between pods
- create additional proxy listening on port 80 and forwarding traffic to nodes
  (incl. load balancing between those nodes) so users can access app now via
  http://domain.tld

Cloud:

- mostly similar to above but...
- provision cloud load balancing service with external IP

- for multiple services of type loadbalancer need another "load-balancer" that
  redirects to different services, say <base-url>/video and <base-url>/apparel

TLS:

- several places where it could be implemented:
  - application level
  - load balancer level
  - proxy server level

--> All of this is conceptionally provided by K8s Ingress Controllers as Layer 7 Load Balancer

(manual alternative on-prem: Nginx, haproxy or traefik as reverse-proxy)

NOTE: By default a k8s cluster does not come with an ingress controller.
Need to deploy this yourself!

Options:

- GCE - GCP http(s) load balancer
- nginx <- maintained by k8s project!
- contour
- haproxy
- traefik
- istio ingress

Ingress Rules:

- used when redirecting traffic based on domain names
- can also contain path definitions
- multiple DNS entries can point to same Ingress controller

Rewrite Target (nginx):

- without target rewrite:
  - http://<ingress-svc>:<port>/path1 -> http://<svc1>:<port>/path1
  - http://<ingress-svc>:<port>/path2 -> http://<svc2>:<port>/path2
- with target rewrite to /:
  - http://<ingress-svc>:<port>/path1 -> http://<svc1>:<port>/
  - http://<ingress-svc>:<port>/path2 -> http://<svc2>:<port>/
- fanciert examples:
  - https://kubernetes.github.io/ingress-nginx/examples/rewrite/

NOTE: In contrast to the Ingress Controller, which can be deployed in any
namespace, but conventionally in "kube-system" or "ingress", Ingress Rules
are namespace-scoped. So you can't do ingress rules across namespaces, but need
to create separate objects for each namespace where applications are running!

Split by path (1 rule, 2 paths):

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: minimal-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
    - http:
        paths:
          - path: /path1
            pathType: Prefix
            backend:
              service:
                name: test1
                port:
                  number: 80
          - path: /path2
            pathType: Prefix
            backend:
              service:
                name: test2
                port:
                  number: 80
```

Split by domain (2 rules, 1 path each)

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: ingress-wear-watch
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
    - host: sub1.my-online-store.com
      http:
        paths:
          - backend:
              service:
                name: test1
                port:
                  number: 80
    - host: sub2.my-online-store.com
      http:
        paths:
          - backend:
              service:
                name: test1
                port:
                  number: 80
```

## K8s Cluster Design and Installation

### Design

Questions:

- Purpose: Eduction, Dev, Testing?
- Cloud or OnPrem
- Workloads: kind, number, app requirements, traffic

Education: minikube, single node cluster
Dev/Testing: multi-node cluster with k3s or GCP/AWS/Azure

Production:
-> HA cluster with multiple master nodes

Storage:

- high performance SSD
- multiple concurrent connections - network based storage
- persistent shared volumes for shared access across multiple pods
- label nodes with specific disk types for use with node selectors

Nodes:

- physical or virtual
- min. 4 nodes (based on actual workload)
- linux x68_64 arch
- no workloads on master nodes (via taint)
- separate ETCD cluster to dedicated nodes

### Infrastructure

No windows-native binaries! :D

- minikube + virtualbox / docker / podman
- kubeadm (requires already provisioned VMs)

| Turnkey Solution                      | Hosted Solutions                           |
| ------------------------------------- | ------------------------------------------ |
| AWS via kOPS, OpenShift, CloudFoundry | K8aaS like GKE, EKS, AKS, OpenShift Online |
| you provision & configure VMs         | provider provisions VMs                    |
| use scripts to deploy cluster         | provider installs K8s                      |
| you maintain VMs                      | provider maintains VMs                     |

### Configure HA

What happens if you loose the master node?

- applications still alive and can be accessed - until things start to fail
- no scheduler, no api-server

Run control plane components in HA!

- api-server: active/active mode
  - all can receive requests and processing them
  - use load balancer in front
- scheduler/controller-manager: active/passive mode
  - cannot run multiple instances since they would interfere with each other,
    e.g. all wanting to create same object
  - leader-election process
- ETCD: own cluster with two possible topologies
  - stacked: run on control plane nodes
    - easier to setup & manage, fewer servers, risk during failures
  - external:
    - less risky, harder to setup, more servers

Remember: only kube api server talks to ETCD!

### ETCD in HA

"ETCD is a distributed reliable key-value store that is Simple, Secure & Fast."

- possible to have multiple ETCD servers in a cluster
- read from or write to any server, cluster will always be consistent
- implementation of read is easy
- writes only go to leader, either directly or forwarded by follower,
  performs the writes and makes sure write is propagated to all followers
- write is only complete if leader gets consent from all followers (see below for details)

Leader election via RAFT protocol:

- random timer is kicked of on all members
- first one that finishes sends request to all others to become leader
- members respond with their vote
- from now on periodically sends info to other members that it's continuing to
  be leader
- if other members do not receive this info (node go down, network issues,...)
  the remaining nodes initiate a new leader-election process

What if a member goes down during a write? When is it considered to be "complete"?

- write is complete if change is written to **majority** of members
- temp. unavailable members will catch up the change
- majority = quorum = N / 2 + 1

!! having 2 instances is like having only 1. it gives no benefit b/c if one
member fails quorum cannot be reached anymore !!

|                 |     |     |     |     |     |     |     |
| --------------- | --- | --- | --- | --- | --- | --- | --- |
| instances       | 1   | 2   | 3   | 4   | 5   | 6   | 7   |
| quorum          | 1   | 2   | 2   | 3   | 3   | 4   | 4   |
| fault tolerance | 0   | 0   | 1   | 1   | 2   | 2   | 3   |

- minimum number of members for HA is 3!
- recommended to choose odd number
- example incident: network segmentation dividing members by 2

### KTHW - K8s The Hard Way (via kubeadm)

K8s cluster deployment via kubeadm steps:

1. provision 1 master and 2 worker nodes
2. install container runtime containerd
3. install kubeadm tool on all nodes
4. initialize master server (install all control plane components)
5. deploy pod network and let all workers join

Basically follow the official docs:

1. Install container runtime, e.g. containerd:

   - https://kubernetes.io/docs/setup/production-environment/container-runtimes/
   - enable IPv4 forwarding & setup bridge traffic rules
   - check systemd vs. cgroupfs drivers

2. Install kubeadm and kubelet in specific version:

   - https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl
   - pin version during install and hold it afterwards

3. Create token (or use the one from installation):

   - https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/
   - depending on CNI network addon, set pod network (default: 10.244.0.0/16)

   ```
   kubeadm token create --print-join-command
   kubeadm init \
     --pod-network-cidr=10.244.0.0/16 \
     --apiserver-advertise-address=<ip-address> \
     --apiserver-cert-extra-sans=controlplane
   ```

4. Create / copy over default kubeconf as stated on the CLI output of kubeadm
5. Install network addon:

   - https://kubernetes.io/docs/concepts/cluster-administration/addons/#networking-and-network-policy

6. Optional: Alias and auto completion for kubectl:

   - https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/

## Troubleshooting

### Apps

https://kubernetes.io/docs/tasks/debug/debug-application/

- check accessibility
- draw map / chart of components
- check every object

- check frontends
- describe services, check ports and selectors/labels
- check pod / deployment specs + ENVs
- check pods are running
- check pod logs

### Controlplane

https://kubernetes.io/docs/tasks/debug/debug-cluster/

- check nodes status
- check controlplane components - either pods or services
  - kube-apiserver
  - kube-controller-manager
  - kube-scheduler
  - kubelet
  - kube-proxy
- check service logs
  - `kubectl logs`
  - `sudo journalctl -u <service>`

### Worker Nodes

- check nodes status -> conditions
  - OutOfDisk
  - MemoryPressure
  - DiskPressure
  - PIDPressure
  - Ready
- check kubelet status
  - right certificates?
  - issued by right CA?

Important kubelet files:

- /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
- /var/lib/kubelet/config.yaml
- /etc/kubernetes/kubelet.conf

### Network

- check pods for IP addess allocation failures etc.
- check if Network Plugin is deployed, e.g. WeaveNet or Flannel

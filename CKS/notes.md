# KillerShell CKS Notes

NOTE: full video course now available on YT free of charge! <br>
https://www.youtube.com/watch?v=d9xfB5qaOfg

# Foundation

## 1. Introduction

- Security Principles
- K8s Security Categories
- K8s Best Practices

Security is complex and a process

Principles:

- Defense in Depth
- Least Privilege
- Limiting attack surface
- Redundancy is good in Security (no DRY - Don't Repeat Yourself)

-> Layered defense system

Security Categories:
(1-2 is already taken care of by cloud provider)

1. Linux Host Operating System Security
   - K8s nodes should only do one thing: k8s
   - reduce attack surface by removing unnecessary apps and keep packages up-to-date
   - runtime security tools
   - find malicious processes
   - restrict IAM/SSH access
2. Kubernetes Cluster Security
   - K8s components (apiserver, kubelet, etcd) should run secure and up-to-date
   - restrict external access
   - use authentication -> authorization -> admission controllers (e.g.
     NodeRestriction, custom policies via OPA)
   - Enable Audis Logging
   - Use Security Benchmark Tools
3. Application Security
   - No hardcoded credentials
   - Use RBAC
   - Container Sandboxing
   - Container Hardening
     - reduce attack surface
     - run as user instead of root
     - RO filesystem
   - Vulnerability scanning
   - mTLS / Service Meshes

=> Talk: K8s Security Best Practices by Ian Lewis from Google
https://www.youtube.com/watch?v=wqsUfvRyYpw

## 2. Create Course K8s Cluster (gcloud)

setup vms

```bash
# master
gcloud compute instances create cks-master --zone=europe-west3-c \
--machine-type=e2-medium \
--image=ubuntu-2004-focal-v20220419 \
--image-project=ubuntu-os-cloud \
--boot-disk-size=50GB

# worker
gcloud compute instances create cks-worker --zone=europe-west3-c \
--machine-type=e2-medium \
--image=ubuntu-2004-focal-v20220419 \
--image-project=ubuntu-os-cloud \
--boot-disk-size=50GB
```

find region near you:
https://cloud.google.com/compute/docs/regions-zones

- Frankfurt = europe-west3-a|b|c
- Berlin = europe-west10-a|b|c

provision nodes

```bash
gcloud compute ssh cks-master
sudo -i
bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/cluster-setup/latest/install_master.sh)

gcloud compute ssh cks-worker
sudo -i
bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/cluster-setup/latest/install_worker.sh)
```

setup firewall for later use

```bash
gcloud compute firewall-rules create nodeports --allow tcp:30000-40000
```

SSH

```
gcloud compute ssh cks-master
```

File locations:

- Identity: ~/.ssh/google_compute_engine
- PubKey: ~/.ssh/google_compute_engine.pub

NOTE: If backspace etc. is not working properly, install terminfo for your
terminal. For me e.g.:

```bash
apt install kitty-terminfo
```

## 3. Killercoda Access

nothing to note here...

## 4. K8s Secure Architecture

- container is running in pod as wrapper on a node
- kubectl -> apiserver -> kubelet
-                  ^----- kube-proxy
- other components: etcd, scheduler, controller manager, cloud controller manager
- all communicate via apiserver
- pod-2-pod communication via CNI
  - implemented by CNI plugins (like calico/weave..)
  - by default every pod can communicate with every other pod
  - can happen without NAT and across all nodes
- PubKey Infrastructure (PKI) with Certfificate Authority (CA)
  - CA is trusted root of all certs inside cluster
  - all cluster certs are signed by this CA
  - used by components to validate each other
  - e.g. apiserver cert, kubelet cert, scheduler cert etc.
  - COMMON PATHS:
    - /etc/kubernetes/pki
    - /etc/kubernetes/pki/etcd
    - /etc/kubernetes/scheduler.conf
    - /etc/kubernetes/controller-manager.conf
    - /etc/kubernetes/kubelet.conf
    - /var/lib/kubelet/pki

Further readings:

- All You Need to Know About Certificates in Kubernetes
  https://www.youtube.com/watch?v=gXz4cq3PKdg
- Kubernetes Components
  https://kubernetes.io/docs/concepts/overview/components
- PKI certificates and requirements
  https://kubernetes.io/docs/setup/best-practices/certificates

## 5. Containers under the hood

### Container and Image

Dockerfile [docker build] Image [docker run] Container / [docker push] Repo

Containers:

- collection of one or more apps
- includes all dependencies
- just a process (that may not see everything) on the Linux kernel

Kernel vs User Space [view below list as inverse stack]

- Hardware
- Kernel Space
  - Linux Kernel
  - Syscall Interface -> getpid(), reboot()
- User Space
  - Libraries -> glibc, libxyz
  - Applications -> firefox, Curl

No matter if apps are containerized or not, they can make direct syscalls
against the host's kernel!

-> can possibly exploit kernel bugs!

Container vs VM:

- VMs have their own OS and kernel
- Container app processes only wrapped in kernel groups

### Linux Namespaces

PID namespace:

- isolates processes from each other
- one process cannot see others
- process ID 10 can exist multiple times, once in every namespace

Mount namespace:

- restricts acces to mounts or root filesystem

Network namespace

- only access certain network devices
- firewall & routing rules & socket port numbers
- not able to see all traffic or contact all endpoints

User namespace

- different set of user IDs used, i.e. user ID 0 inside one ns can be different
  from user ID 0 in another
- don't use the host root user 0 inside a container

### Container Isolation

- namespaces restrict what processes can see
  - other processes, useres, filesystem
- cgroups only restrict resource usage of processes
  - RAM, disk, CPU

### Container Tools

- Docker: container runtime + tool for managing containers & images
  (not supported by k8s 1.22+ anymore!)
- ContainerD: other popular container runtime
- Crictl: CLI for CRI-compatible container runtimes like containerd
- Podman: Tool for managing containers and images

crictl config path:

```
> cat /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
```

### PRACTICE: PID Namespace

Docker automatically wraps containers in namespaces, so the following created sleep processes cannot see each other by default:

```
docker run --name c1 -d ubuntu sh -c "sleep 1d"
docker run --name c2 -d ubuntu sh -c "sleep 999d"
docker exec c1 ps aux
docker exec c2 ps aux
```

By changing only a small option, they will now run in the same ns and see each
other:

```
docker rm c2 --force
docker run --name c2 -d --pid=container:c1 ubuntu sh -c "sleep 999d"
docker exec c1 ps aux
docker exec c2 ps aux
```

Further reading:

- Liz Rice: What have containers done for you lately?
  https://www.youtube.com/watch?v=MHv6cWjvQjM

# Cluster Setup

## 6. Cluster Setup - Network Policies

### Network Policies

- firewall rules in k8s
- implemented by Network Plugin CNI like calico / weave
- created on namespace level
- restrict ingress and/or egress for group of pods based on certain rules and
  conditions

BY DEFAULT: every pod can access every other pod! -> pods are not isolated!

- can have multiple NetPols for same group of pods (podSelector)
- union of them will apply
- order does not matter
- check: https://github.com/killer-sh/cks-course-environment/blob/master/course-content/cluster-setup/network-policies/merge-multiple/merged.yaml

Best Practices:

- create default-deny policy

  ```
  k run --image nginx frontend
  k run --image nginx backend

  k expose pod frontend --port 80
  k expose pod backend --port 80

  # this still works
  k exec frontend -- curl backend
  k exec backend -- curl frontend
  ```

- create and apply default deny policy

  ```yaml
  # deny all incoming and outgoing traffic from all pods in namespace default
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
  name: default-deny
  namespace: default
  spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ```

- explicitly allow ingress and egress from/to those pods again

  ```yaml
  # allows frontend pods to communicate with backend pods
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: frontend
    namespace: default
  spec:
    podSelector:
      matchLabels:
        run: frontend
    policyTypes:
      - Egress
    egress:
      - to:
          - podSelector:
              matchLabels:
                run: backend
  ```

  ```yaml
  # allows backend pods to have incoming traffic from frontend pods
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: backend
    namespace: default
  spec:
    podSelector:
      matchLabels:
        run: backend
    policyTypes:
      - Ingress
    ingress:
      - from:
          - podSelector:
              matchLabels:
                run: frontend
  ```

- still does not work anymore because default-deny even prevents DNS resolution!
  SOLUTION: either use IP from `k get pods -owide` or explicitly allow DNS by
  altering the default-deny policy like so:

  ```yaml
  # deny all incoming and outgoing traffice from all pods in ns default
  # but allow DNS traffic
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
  name: deny
  namespace: default
  spec:
  podSelector: {}
  policyTypes:
    - Egress # specify below for DNS
    - Ingress # this is still deny-all
  egress:
    - ports:
        - port: 53
          protocol: TCP
        - port: 53
          protocol: UDP
  ```

Example tests taken from one of the KillerCoda scenarios

```
# these should work
k -n space1 exec app1-0 -- curl -m 1 microservice1.space2.svc.cluster.local
k -n space1 exec app1-0 -- curl -m 1 microservice2.space2.svc.cluster.local
k -n space1 exec app1-0 -- nslookup tester.default.svc.cluster.local
k -n kube-system exec -it validate-checker-pod -- curl -m 1 app1.space1.svc.cluster.local

# these should not work
k -n space1 exec app1-0 -- curl -m 1 tester.default.svc.cluster.local
k -n kube-system exec -it validate-checker-pod -- curl -m 1 microservice1.space2.svc.cluster.local
k -n kube-system exec -it validate-checker-pod -- curl -m 1 microservice2.space2.svc.cluster.local
k -n default run nginx --image=nginx:1.21.5-alpine --restart=Never -i --rm  -- curl -m 1 microservice1.space2.svc.cluster.local
```

## 7. Cluster Setup - GUI Elements

- only expose services externally if absolutely needed
- cluster internal services / dashboards can also be accessed using
  `kubectl port-forward`

Famous Tesla Hack 2018:

- K8s dashboard had too many privileges w/o RBAD or too broad roles
- K8s dashboard was exposed to the internet (against default)

K8s Proxy:

- create proxy between localhost and K8s apiserver
- uses connection as configuerd in kubeconfig
- allows API access locally just over http and w/o authentication
  `http://localhost:8001/api/v1/...`
- http via proxy -> kubectl -> httpS to apiserver

K8s port-forward:

- similar to proxy but more generic
- forwards connections from localhost-port to pod-port
- can be used for all TCP traffic, not only HTTP
- example: dashboard runs on pod with internal cluster ip:port 10.1.2.3:443
  `tcp://localhost:1234 -> <IP>:443
- if apiserver itself runs in a pod, port-forward can also be used to assess it

Ingress:

- e.g. nginx, traefik
- use with DNS and proper domain
- needs proper authentication methods like LDAP, http-auth etc.

For K8s dashboard particularly:
https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/README.md

NOTE: nowadays dashboard is installed via helm, not manifest anymore.

```
# install helm: https://helm.sh/docs/intro/install
helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/
helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard
```

TODO: check Q&A for up-to-date nginx ingress

## 8. Secure Ingress

K8s Service recap:

- services always point to pods, never to deployments or daemonsets via labels
- clusterIP svc type means: internal ip + internally reachable via DNS
- nodeport basically creates clusterIP + opens port on every node (nodeport)
- loadbalancer basically creates nodeport + communicate with cloud provider

Ingress:

- nginx ingress = pod with nginx reverse-proxy running in it
- nginx config created by ingress controller - never have to touch it manually

### Nginx Example

Request -> NodePort -> Nginx Ingress /service1 -> ClusterIP -> pod1
...................................../service2 -> ClusterIP -> pod2

NOTE: this only works with the outdated copy of ingress-nginx provided by
killersh in their github repo:

https://github.com/killer-sh/cks-course-environment/blob/master/course-content/cluster-setup/secure-ingress/nginx-ingress-controller.yaml

Create ingress rules

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: nginx # newer Nginx-Ingress versions NEED THIS
  rules:
    - http:
        paths:
          - path: /service1
            pathType: Prefix
            backend:
              service:
                name: service1
                port:
                  number: 80

          - path: /service2
            pathType: Prefix
            backend:
              service:
                name: service2
                port:
                  number: 80
```

Create test pods and expose them

```
k run pod1 --image nginx
k run pod2 --image httpd
k expose pod pod1 --port 80 --name service1
k expose pod pod2 --port 80 --name service2
```

Check from laptop

```
curl http://<external-IP>:<ingress-nginx-controller_service-http-nodeport>

# for me:
curl http://34.107.113.180:31143
curl http://34.107.113.180:31143/service1
curl http://34.107.113.180:31143/service2
```

Now secure ingress via HTTPS. (port already is setup by k8s services!)

First check if it works already:

```
curl https://<external-IP>:<ingress-nginx-controller_service-https-nodeport>

# for me:
curl https://34.107.113.180:32214
```

Will complain about self-signed certs. Let's check in more detail:

```
> curl https://34.107.113.180:32214
curl: (60) SSL certificate problem: self-signed certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

Ask to ignore self-signed with `-k` and check cert details with `-v`
(NOTE "Fake Certificate")

```
> curl -kv https://34.107.113.180:32214
* [...]
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN: server accepted h2
* Server certificate:
*  subject: O=Acme Co; CN=Kubernetes Ingress Controller Fake Certificate
*  start date: Nov  1 09:44:41 2023 GMT
*  expire date: Oct 31 09:44:41 2024 GMT
*  issuer: O=Acme Co; CN=Kubernetes Ingress Controller Fake Certificate
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
* [...]
```

Create own (still self-signed for testing...) certificate

```bash
# -x509 -> output cert instead of CSR
# -nodes -> "No DES" -> will not encrypt private key in a PKCS#12 file
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# leave everything as default, use CN = secure-ingress.com
```

Create secret of type TLS to be referenced

```bash
k create secret tls secure-ingress --cert=cert.pem --key=key.pem
```

Edit previous ingress manifest and include TLS section and hosts

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: nginx # newer Nginx-Ingress versions NEED THIS
  tls:
    - hosts:
        - secure-ingress.com
      secretName: secure-ingress
  rules:
    - host: secure-ingress.com
      http:
        paths:
          - path: /service1
            pathType: Prefix
            backend:
              service:
                name: service1
                port:
                  number: 80
          - path: /service2
            pathType: Prefix
            backend:
              service:
                name: service2
                port:
                  number: 80
```

For plain IP, still old "fake" cert will be used, because our own only is set
up for the specific domain "secure-ingress.com".

Instead of creating a host-file entry, better use `-resolve` feature of curl!

Check now, that our own self-signed cert is used.

```
> curl -kv https://secure-ingress.com:32214/service1 --resolve secure-ingress.com:32214:34.107.113.180
* [...]
* Server certificate:
*  subject: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd; CN=secure-ingress.com
*  start date: Nov  1 10:09:00 2023 GMT
*  expire date: Oct 31 10:09:00 2024 GMT
*  issuer: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd; CN=secure-ingress.com
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
* [...]
```

### NOTES from comments

In the exam, there will be questions regarding securing the apiserver and ETCD
relating to TLS versions.

Check here:
https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver

The relevant arguments are:

- for the API server manifest

  ```
   --tls-min-version=VersionTLS12
   --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ```

- for the etcd manifest

  ```
  etcd -h  | grep -A1 cipher-suites
  ```

  ```
   --cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ```

## 9. Node Metadata Protection

Nodes connect to metadata server managed by cloud provider to fetch info about
service accounts, credentials etc. used to spin up their services.

- metadata api reachable from VMs by default
- can contain cloud credentials for VMs/nodes
- can contain provisioning data like kubelet credentials

-> pods can also contact this server!

out-of-scope: cloud-instance account has only the necessary permission

### Example

Fetch metadata from gcloud, check:

- https://cloud.google.com/compute/docs/metadata/overview
- https://cloud.google.com/compute/docs/metadata/querying-metadata

```bash
# from master node
curl "http://metadata.google.internal/computeMetadata/v1/instance/image" -H "Metadata-Flavor: Google"

# from pod
k run test --image nginx -i --rm --restart=Never -- curl -s "http://metadata.google.internal/computeMetadata/v1/instance/image" -H "Metadata-Flavor: Google" -w "\n"
```

How to protect? -> using NetworkPolicy

Allow egress to world except metadata server

```yaml
# all pods in namespace cannot access metadata endpoint
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-deny
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
```

Allow only for certain pods

```yaml
# only pods with label are allowed to access metadata endpoint
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-allow
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: metadata-accessor
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 169.254.169.254/32
```

### Misc

- Metadata server on AWS:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- Metadata server on Azure:
  https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux

Test (ping) connections on arbitrary ports:

```
nc -v <IP> <PORT>
```

### KillerCoda Example

How to verify:

```
# these should work
k exec trust-0 -- nc -v 1.1.1.1 53
k exec trust-0 -- nc -v -w 1 www.google.de 80
k exec no-trust-0 -- nc -v -w 1 www.google.de 80

# these should not work
k exec no-trust-0 -- nc -v 1.1.1.1 53
```

## 10. CIS Benchmarks

CIS - Center for Internet Security

- best practices for the secure configuration of a target system
- covering more than 14 technology groups (so not only K8s)

https://www.cisecurity.org/benchmark/kubernetes -> download PDF
https://downloads.cisecurity.org/#/

NOTE: kubeadm by default already applies CIS best practices!

References for GKE:
https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks

### Automation via kube-bench

GitHub: https://github.com/aquasecurity/kube-bench

-> simply start in container as described here:
https://github.com/aquasecurity/kube-bench/blob/main/docs/running.md#running-inside-a-container

```
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -t docker.io/aquasec/kube-bench:latest --version 1.18
```

### KillerCoda Example

Run single benchmark on ubuntu-installed kube-bench

```
kube-bench run --targets master --check 1.2.20
```

Watch apiserver pod / container during restart

```
watch crictl ps
```

### Further Reading

- Talk: Consistent Security Controls through CIS Benchmarks
  https://www.youtube.com/watch?v=53-v3stlnCo
- Benchmark for Docker
  https://github.com/docker/docker-bench-security

## 11. Verify Platform Binaries

Theory & Hashes

- create fingerprints (hashes) of files
- one-way algorithms (like a lossfull compression algorithm)-> e.g. SHA, MD5, ...

Verify K8s releases

- download tarball from github
- check sha512 hash against the one listed in the changelog file
- extract tar and `<tar>/server/bin/kube-apiserver --version`

Verify binaries running in cluster

- cannot exec into hardened apiserver pod -> no sh/bash installed!
- find PID of process using `ps aux | grep kube-apiserver`
- search for binary in `/proc` path (WATCH TRAILING SLASH in root/ !)

  ```
  find /proc/18421/root/ | grep kube-api
  find /proc/18421/root/ -name "*kube-api*"

  # calculate hash
  sha512sum /proc/18421/root/usr/local/bin/kube-apiserver
  ```

# Cluster Hardening

## 12. RBAC

> Role-based Access Control (RBAC) is a method of regulating access to computer
> or network resources based on the roles of individual users within your
> organization.

In k8s enabled via

```
--authorization-mode stringSlice  Default: [AlwaysAllow]
# ordered list of plug-ins to do authorizaion on secure port. Comma-delimited
# list of: AlwaysAllow, AlwaysDeny,ABAC,Webhook,RBAC,Node
```

- in kubeadm clusters, RBAC is enabled by default!
- works with roles and rolebindings
- specify what is ALLOWED, everything else is DENIED -> whitelisting only

POLP principle:

> Principle Of Least Priviledge: Only access to data or information that is
> necessary for the legitimate purpose

Reminder: there are namespaced and cluster resources

```
kubectl api-resources --namespaced=true
kubectl api-resources --namespaced=false
```

Where are permissions _available_?
e.g. can edit pods, can read secrets

- Role: in one namespace
- ClusterRole: in all namespaces + non-namespaced

Where are permissions _applied_?
"bind a role to something (user or serviceaccount)"

- RoleBinding: in one namespace
- ClusterRoleBinding: in all namespaces + non-namespaced

NOTE!: ClusterRoles apply to all **current** and **future** resources!

Valid combinations:

- role + rolebinding: permissions available and applied in one ns
- c.role and c.rolebinding: perm. available and applied everywhere
- c.role and rolebinding: available everywhere but applied only in one

Permissions are additive:

- get,delete secrets + get secrets = get,delete secrets

Always verify RBAC rules via `auth can-i`!

```
kubectl auth can-i delete pod --as user username
kubectl auth can-i create deployments --as system:serviceaccount:namespace:serviceaccountname
```

### Accounts

- for serviceaccounts -> use k8s api
- for normal users ->no k8s user resource

User management:

- cluster-independent user management service assumed
  (possibly from cloud provider)
- user = someone with key & certificate signed by cluster's CA
- username is common name of cert: /CN=jane

Create new user:

```
openssl: create key & CSR -> k8s API <- CA -> download CERT -> use KEY/CERT

```

Leaks & Invalidation

- no way to invalidate a certificate
- if a cert has been leaked:
  - remove all access via RBAC and username cannot be used until cert is expired
  - or create new CA and re-issue all certs

Entire procedure as code:

```
openssl genrsa -out jane.key 2048
openssl req -new -key jane.key -out jane.csr # only set Common Name = jane

# create CertificateSigningRequest with base64 jane.csr
# https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests
cat jane.csr | base64 -w 0

# approve CSR and extract certificate
k certificate approve jane
k get csr jane -o yaml
echo <ENCODED_CERT> | base64 -d > jane.crt

# add new KUBECONFIG
# ...with reference to files...
k config set-credentials jane --client-key=jane.key --client-certificate=jane.crt
# ...or with embedded files...
k config set-credentials jane --client-key=jane.key --client-certificate=jane.crt --embed-certs
k config view

k config set-context jane --cluster=kubernetes --user=jane
k config get-contexts
k config use-context jane
```

### KillerCoda Examples

1. Grant view permissions for all but one namespace

   - there is no deny-RBAC as of now
   - need to grant in each available ns except one
   - can utilize xargs

   ```
   k get ns --no-headers | cut -f1 -d ' ' | xargs -I{} kubectl create rolebinding smoke-view --clusterrole view --user smoke -n {}
   k delete rolebindings smoke-view -n kube-system
   ```

2. Allow only to _list_ secrets but not to view their content

   - not possible using plain K8s RBAC!
   - even with verb=list, one could simply run `get -o yaml` and see data!

   ```
   # NOT SUFFICIENT!
   k -n applications create role list-secrets --verb list --resource secrets
   k -n applications create rolebinding ...
   ```

3. Manually sign CSR using K8s CA

```
openssl x509 -req -in <CSR> -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out <CERT> -days 365
```

## 13. Caution with ServiceAccounts

- normal users: no k8s resource, external IDM assumed
- serviceAccounts: resource managed by k8s api

- default SA "default" in every namespace to used by pods
- can be used to talk to k8s api via token

### Create and retrieve SA-tokens

Create temporary token for a serviceaccount

```
k create token <serviceaccount>
```

Check content by inserting e.g. into jwt.io

```
HEADER:
{
  "alg": "RS256",
  "kid": "BHl_x4799A_VvlblumemYvwgxcZEc3iq0ufDkpSbO6Y"
}
```

```
PAYLOAD:
{
  "aud": [
    "https://kubernetes.default.svc.cluster.local"
  ],
  "exp": 1698929688,
  "iat": 1698926088,
  "iss": "https://kubernetes.default.svc.cluster.local",
  "kubernetes.io": {
    "namespace": "default",
    "serviceaccount": {
      "name": "accessor",
      "uid": "7536f975-4783-470a-8b2f-a1c79212a6b4"
    }
  },
  "nbf": 1698926088,
  "sub": "system:serviceaccount:default:accessor"
}
```

Use serviceaccounts in pod manifests:

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: accessor
  name: accessor
spec:
  serviceAccountName: accessor
  containers:
    - image: nginx
      name: accessor
      resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
status: {}
```

Apply pod and check SA file mounts:

```
k run accessor --image nginx --dry-run=client -o yaml > pod.yaml
# add SA entry
k apply -f pod.yaml
k exec -it accessor -- bash

> mount | grep service
tmpfs on /run/secrets/kubernetes.io/serviceaccount type tmpfs (ro,relatime,size=3900180k,inode64)

> ls /run/secrets/kubernetes.io/serviceaccount
ca.crt	namespace  token
```

### API Calls

In a pod run

```
env | grep KUBERNETES_SERVICE_HOST

> curl -k https://$KUBERNETES_SERVICE_HOST
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {},
  "code": 403
}
```

If no payload is passed we will be identified as "anonymous".

Add auth header with bearer token:

```
token=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
ip=$KUBERNETES_SERVICE_HOST

> curl -k https://$ip -H "Authorization: Bearer $token"
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "forbidden: User \"system:serviceaccount:default:accessor\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {},
  "code": 403
}
```

-> correctly authenticated, but not authorized to do anything b/c missing RBAC

### Safety Measures

1. Does my pod need to talk to the K8s api? -> usually not.

   Disable automount: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting

   - per serviceaccount

     ```yaml
     piVersion: v1
     kind: ServiceAccount
     metadata:
       name: build-robot
     automountServiceAccountToken: false
     ```

   - per pod

     ```yaml
     apiVersion: v1
     kind: Pod
     metadata:
       name: my-pod
     spec:
       serviceAccountName: build-robot
       automountServiceAccountToken: false
     ```

2. Limit ServiceAccount Permissions using RBAC

   If all pods use default SA and you give this SA more permissions, all pods
   have these permissions too! -> PULP principle!

## Restrict API access

3 levels for API requests:

- authentication - who are you?
- authorization - are you allowed to?
- admission control - e.g. has limit of pods been reached?
  - custom ACs
  - 3rd party ACs
  - OPA can act as AC

API requests are always tied to:

- normal user
- service account
- or treated as anonymous request

Every request must authenticate if not treated as anonymous.

Restrictions:

1. don't allow anonymous access
2. close insecure port
3. don't expose apiserver to outside
4. restrict access from nodes to API (NodeRestriction)
5. prevent unauthorized access via RBAC (see §14)
6. prevent pods from accessing API (see §15)
7. place apiserver port behind firewall / allow only certain ip ranges if need
   to expose to outside

### Anonymous access

Set via CLI argument

```
kube-apiserver --anonymous-auth=true|false
```

From v1.6+, anonymous access is enabled by default if

- auth mode is other than AlwaysAllow
- but ABAC and RBAC require explicit authorizaion for anonymous

Check:

```
# on controlplane
> curl -k https://localhost:6443
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {},
  "code": 403
}

# after setting `--anonymous-auth=false`
> curl -k https://localhost:6443
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```

NOTE: Why is it enabled after all by default?
-> kube-apiserver needs it for its own liveness probes!

### Insecure Access

NOTE: Since v1.20 insecure access is no longer possible!

With this it was previously possible to circumvent authentication &
authorization completely.

### Manual API requests

Use data from kubeconfig to perform manual API requests:

```
k config view --raw
```

Extract, decode and save CA and user cert & key.
Extract IP from `clusters[name=kubernetes].cluster.server`.

```
curl https://10.156.0.2:6443 --cacert ca
curl https://10.156.0.2:6443 --cacert ca --cert crt --key key
```

### External APIserver access

Edit "kubernetes" service in default namespace and change type from ClusterIp
to NodePort. (firewall rules have been created beforehand in gcloud)

Copy nodeport

```
> k get svc
NAME         TYPE       CLUSTER-IP   EXTERNAL-IP   PORT(S)         AGE
kubernetes   NodePort   10.96.0.1    <none>        443:30923/TCP   2d4h
```

TODO: probably different for "normal" k8s clusters? -> check

```
# as anonymous use
curl -k https://external-ip:node-port
curl -k https://34.107.113.180:30923
```

Now copy over kubeconf and replace internal-IP:6443 with external-IP:nodeport

```
k config view --raw
```

On local machine:

```
> k --kubeconfig conf get pod
Unable to connect to the server: tls: failed to verify certificate: x509: certificate is valid for 10.96.0.1, 10.156.0.2, not 34.107.113.180
```

Inspect certificate

```
openssl x509 -in /etc/kubernetes/pki/apiserver.crt -noout -text
> X509v3 Subject Alternative Name:
>   DNS:cks-master, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, IP Address:10.96.0.1, IP Address:10.156.0.2
```

Patch DNS resolution via `/etc/hosts` and use "kubernetes" also in the kubeconf
file

```
# in /etc/hosts
<external-IP> kubernetes
```

### NodeRestriction AdmissionController

Enable via

```
kube-apiserver --enable-admission-plugins=NodeRestriction
```

- limits the node labels a kubelet can modify
  - may modify only own labels and only certain of them
  - may modify only labels of pods running on this very node
- ensure secure workload isolation via labels
  - imagine some nodes run "more secure" and are identified by labels.
    an intruder could now just give a "harmful" node this label and can run
    secure workloads
- for kubeadm clusters enabled by default

Example:

On each k8s node installed with kubeadm we find the kubeconfig used by the
kubelet to communicate with the apiserver under `/etc/kubernetes/kubelet.conf`.

```
export KUBECONFIG=/etc/kubernetes/kubelet.conf

# allowed
k get pod
k label node this-worker label=value

# forbidden
k get ns
k label node controlplane label=value

# also forbidden!
k label node this-worker node-restriction.kubernetes.io/something=yes
```

K8s does not allow on a node to set its own labels with prefix
`node-restriction.kubernetes.io` because of the NodeRestriction.

-> this allows to run workloads securely only on specified nodes.

Further reading:
https://kubernetes.io/docs/concepts/security/controlling-access

### APIserver debugging

Log locations to check:

- /var/log/pods
- /var/log/containers
- crictl ps + crictl logs
- docker ps + docker logs (in case when Docker is used)
- kubelet logs: /var/log/syslog or journalctl

Further reading:
https://kubernetes.io/docs/tasks/debug/debug-cluster/crictl/

## 15. Upgrade Kubernetes

Why update frequently?

- support
- security fixes
- bug fixes
- stay up-to-date for dependencies

Release cycle for major.minor.patch version:

- minor version every 3 months
- no LTS versions

Support:

- maintenance release branches for the most recent 3 minor releases

> Applicable fixes, including security fixes, may be backported to those three
> release branches, depending on severity and feasability.

Version restrictions.
Check: https://kubernetes.io/docs/setup/release/version-skew-policy

1. First upgrade master component
   - apiserver, controller-manager, scheduler
   - need to be same minor version as apiserver OR one below
2. Second upgrade worker components
   - kubelet, kube-proxy
   - need to be same minor version as apiserver OR two below
3. Upgrade kubectl
   - can be +/- one minor version relativ to apiserver

Application reliability:

- graceperiod / terminating state
- pod lifecycle events
- PodDisruptionBudget

### Update Procedure

Check:
https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade

```
# drain
# > CONTROLPLANE:
kubectl drain cks-controlplane
# > WORKERNODE:
kubectl drain cks-node

# upgrade kubeadm
apt-get update
apt-cache show kubeadm | grep 1.22
apt-mark unhold kubeadm
apt-mark hold kubectl kubelet
apt-get install kubeadm=1.22.5-00
apt-mark hold kubeadm

# kubeadm upgrade
kubeadm version # correct version?

# > CONRTOLPLANE:
kubeadm upgrade plan
kubeadm upgrade apply 1.22.5
# > WORKERNODE:
kubeadm upgrade node

# kubelet and kubectl
apt-mark unhold kubelet kubectl
apt-get install kubelet=1.22.5-00 kubectl=1.22.5-00
apt-mark hold kubelet kubectl

# restart kubelet
service kubelet restart
service kubelet status

# > CONTROLPLANE-only: show result
kubeadm upgrade plan
kubectl version

# uncordon
# > CONTROLPLANE:
kubectl uncordon cks-controlplane
# > WORKERNODE:
kubectl uncordon cks-node
```

# Microservice Vulnerabilities

## 16. Manage K8s Secrets

### Extracting from pods

Why secrets? -> Cannot simply commit secrets to repos in cleartext.

Two options to consume k8s secrets in a pod:

- load as environment variable
- mount as file

Say we have a pod running on a worker node that consumes a secret via apiserver:
`secrets @ etcd <-> apiserver <-> kubelet on worker <-> containerd runtime`

How to extract secrets given you have access over a nodes' container runtime?

1. Environment variables

   - Find container ID via `crictl ps`
   - Run either

     ```
     crictl inspect d1cb3abca5571 | jq ".info.config.envs"
     crictl inspect d1cb3abca5571 | jq ".info.runtimeSpec.process.env"
     ```

2. File mounts

   - Find mounts

   ```
   # directly check hostPath entry for secret mounts
   crictl inspect d1cb3abca5571 | jq ".status.mounts"
   crictl inspect d1cb3abca5571 | jq ".info.config.mounts"
   crictl inspect d1cb3abca5571 | jq ".info.runtimeSpec.mounts"
   ```

   - OR find PID

   ```
   crictl inspect d1cb3abca5571 | jq -r ".info.pid"
   crictl inspect d1cb3abca5571 | less # + full-text search "pid"

   ps aux | grep 26580
   ```

   - and earch PID's root filesystem

   ```
   find /proc/26580/root/etc/secret1
   ```

-> root user on node can see all ENV-based secrets!

NOTE: using just the kubelet's kubeconfig that would not be possible because of
missing RBAC permissions for user "system:node:cks-worker"!

### Extracting from ETCD

Find correct credentials for connecting to ETCD in kube-apiserver manifest:

```
grep "etcd" /etc/kubernetes/manifests/kube-apiserver.yaml

export ETCDCTL_API=3
p="/etc/kubernetes/pki"

# check
# NOTE: endpoint is using the default value and running on same node (localhost)
etcdctl --cert=$p/apiserver-etcd-client.crt --key=$p/apiserver-etcd-client.key --cacert=$p/etcd/ca.crt endpoint health
```

Extract resources

NOTE: pattern for k8s is `/registry/resource-type/namespace/resource-name`

```
> etcdctl --cert=$p/apiserver-etcd-client.crt --key=$p/apiserver-etcd-client.key --cacert=$p/etcd/ca.crt get /registry/secrets/default/secret2

k8s


v1Secret

secret2default"*$b5572183-d7e3-4611-a68a-95caa9038bf82㒪a
kubectl-createUpdatev㒪FieldsV1:-
+{"f:data":{".":{},"f:pass":{}},"f:type":{}}B
pas12345678Opaque"


# or better readable
> etcdctl --cert=$p/apiserver-etcd-client.crt --key=$p/apiserver-etcd-client.key --cacert=$p/etcd/ca.crt get /registry/secrets/default/secret2 | hexdump -C

00000000  2f 72 65 67 69 73 74 72  79 2f 73 65 63 72 65 74  |/registry/secret|
00000010  73 2f 64 65 66 61 75 6c  74 2f 73 65 63 72 65 74  |s/default/secret|
00000020  32 0a 6b 38 73 00 0a 0c  0a 02 76 31 12 06 53 65  |2.k8s.....v1..Se|
00000030  63 72 65 74 12 cb 01 0a  ae 01 0a 07 73 65 63 72  |cret........secr|
00000040  65 74 32 12 00 1a 07 64  65 66 61 75 6c 74 22 00  |et2....default".|
00000050  2a 24 62 35 35 37 32 31  38 33 2d 64 37 65 33 2d  |*$b5572183-d7e3-|
00000060  34 36 31 31 2d 61 36 38  61 2d 39 35 63 61 61 39  |4611-a68a-95caa9|
00000070  30 33 38 62 66 38 32 00  38 00 42 08 08 9c e3 92  |038bf82.8.B.....|
00000080  aa 06 10 00 8a 01 61 0a  0e 6b 75 62 65 63 74 6c  |......a..kubectl|
00000090  2d 63 72 65 61 74 65 12  06 55 70 64 61 74 65 1a  |-create..Update.|
000000a0  02 76 31 22 08 08 9c e3  92 aa 06 10 00 32 08 46  |.v1".........2.F|
000000b0  69 65 6c 64 73 56 31 3a  2d 0a 2b 7b 22 66 3a 64  |ieldsV1:-.+{"f:d|
000000c0  61 74 61 22 3a 7b 22 2e  22 3a 7b 7d 2c 22 66 3a  |ata":{".":{},"f:|
000000d0  70 61 73 73 22 3a 7b 7d  7d 2c 22 66 3a 74 79 70  |pass":{}},"f:typ|
000000e0  65 22 3a 7b 7d 7d 42 00  12 10 0a 04 70 61 73 73  |e":{}}B.....pass|
000000f0  12 08 31 32 33 34 35 36  37 38 1a 06 4f 70 61 71  |..12345678..Opaq|
00000100  75 65 1a 00 22 00 0a                              |ue.."..|
00000107


# list entries
> etcdctl [...] get /registry/secrets/default --prefix --keys-only
```

### Encrypting secrets at rest in ETCD

Check: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/

- apiserver is the only component talking to ETCD, so it should be responsible
  to encrypt and decrypt secrets
- create encryption configuration and pass to apiserver config via argument
  `--encrypt-provider-config`
  NOTE:
  - providers are given as a list
  - for encryption, only first in the list is used
  - if this is `identity {}`, then secrets will be stored as plain text
  - for decryption, all providers can be used
  - kms v2 > kms v1 > secretbox > aes-gcm > aes-cbc
    (check https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#providers)

Reduced example config:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: cGFzc3dvcmRwYXNzd29yZA== # needs to be 16,24 or 32 chars!
      - identity: {} # <- still need this in order to READ unencrypted secrets!
```

NOTE:
Applying a new configuration only affects newly created secrets!
Re-encrypt all existing ones via

```
kubectl get secrets -A -o json | kubectl replace -f -
```

Applying encryption settings to kube-apiserver manifest:

1. create config (incl. folder) in file /etc/kubernetes/etcd/ec.yaml
2. in apiserver manifest add

- argument

  ```
  - --encryption-provider-config=/etc/kubernetes/etcd/ec.yaml
  ```

- mount directory

  ```
  - hostPath:
    path: /etc/kubernetes/etcd
    type: DirectoryOrCreate
    name: etcd
  ```

- volume mount

  ```
  - mountPath: /etc/kubernetes/etcd
    name: etcd
    readOnly: true
  ```

3. check logs if apiserver comes up again

   ```
   tail -f /var/log/pods/kube-system_kube-apiserver-cks-master_0e185ad3b095c391ec8937351551f432/kube-apiserver/4.log

   > "command failed" err="error while parsing file: resources[0].providers[0].aescbc.keys[0].secret: Invalid value: \"REDACTED\": secret is not of the expected length, got 8, expected one of [16 24 32]"
   ```

   -> this means chosen key is only 8 chars long, but only 16/24/32 are allowed

4. Create new secret and check if
   - old and new ones can be accessed by kubectl
   - hexdump of new secret contains `k8s:enc:aescbc:v1:key` as prefix

Example encrypted secret:

```
00000000  2f 72 65 67 69 73 74 72  79 2f 73 65 63 72 65 74  |/registry/secret|
00000010  73 2f 64 65 66 61 75 6c  74 2f 73 65 63 72 65 74  |s/default/secret|
00000020  33 0a 6b 38 73 3a 65 6e  63 3a 61 65 73 63 62 63  |3.k8s:enc:aescbc|
00000030  3a 76 31 3a 6b 65 79 3a  6d f7 24 9a 1d b7 3b 0c  |:v1:key:m.$...;.|
00000040  f4 7d 03 66 da 02 b9 8a  59 79 0f ac 86 51 53 c9  |.}.f....Yy...QS.|
00000050  5e 17 d3 8b 60 57 44 4a  64 25 14 e6 ac 6d f6 7c  |^...`WDJd%...m.||
00000060  1f ec 3c 51 bd 84 21 8d  97 9d f6 3f 53 c7 db 82  |..<Q..!....?S...|
00000070  27 fb 66 a8 17 60 97 8b  70 7e 1f 6b 35 50 78 fd  |'.f..`..p~.k5Px.|
00000080  e1 0f 56 15 6e d4 96 05  c1 0a 9f a1 63 70 22 8f  |..V.n.......cp".|
00000090  9d ef ca 88 c4 fc 03 7e  80 7f 9d 1b ce 42 82 55  |.......~.....B.U|
000000a0  02 73 36 09 7e e6 f4 a2  81 b4 f7 c9 f4 d5 25 8b  |.s6.~.........%.|
000000b0  37 b7 14 df ff ba 48 31  37 9a 89 1c aa 8a cc a1  |7.....H17.......|
000000c0  db 25 89 f3 40 1b 2a 0d  12 c5 31 b0 33 61 c6 c7  |.%..@.*...1.3a..|
000000d0  dc 27 92 5b 08 a5 8c 48  3b 4d 1a 3e 74 20 e2 4c  |.'.[...H;M.>t .L|
000000e0  6d c3 3b 5a 8c a5 51 27  80 cc 6f 33 13 58 9b 35  |m.;Z..Q'..o3.X.5|
000000f0  18 b0 4d ad 02 f6 65 b4  95 59 51 a8 66 dc ee c0  |..M...e..YQ.f...|
00000100  2f 33 e7 75 f8 86 43 68  27 81 78 dd 20 aa 00 b3  |/3.u..Ch'.x. ...|
00000110  af 78 fe 89 3e d7 c8 82  cc 4c 0d 51 1b 34 ef 8b  |.x..>....L.Q.4..|
00000120  9a c3 a1 ad fc 08 33 2f  1e cb 12 c9 54 17 ff 36  |......3/....T..6|
00000130  87 13 b1 15 9c a0 b7 32  0a                       |.......2.|
00000139
```

5. Re-encrypt all secrets

   ```
   k get secret -A -o json | k replace -f -
   ```

### Production Settings

In the previous example, we used a static key with aes-cbc, which is not really
considered best-practices.

In production, you should use the kms provider using an external 3rd party tool
like AWS KMS or HashiCorp Vault (which also works with the kms provider).

Further reading:

- K8s docs:
  https://kubernetes.io/docs/concepts/security/secrets-good-practices/
- B. Ritter: Secret Management in K8s
  https://www.youtube.com/watch?v=L8Ui0ogIW-k
- Older talk featuring Kubernetes Secrets and Conjur:
  https://www.cncf.io/webinars/kubernetes-secrets-management-build-secure-apps-faster-without-secrets
- Base64 is no encryption:
  https://www.youtube.com/watch?v=f4Ru6CPG1z4

## 17. Container Runtime Sandboxes

### Sandboxes

K8s can only be as secure as the container runtime is!

> "Containers are not contained."
> Just because it runs in a container does not mean it is more protected!

- all container processes eventually run on the same kernel
- if processes have access to kernel, they effectively have access to all other
  containers and the host processes

Sandbox context of security = additional layer to reduce attack surface

- don't come for free
- more resources needed
- might be better for smaller containers
- not good for syscall heavy workloads (like ?)
- no direct access to hardware

```
Hardware
Kernel Space
  Linux Kernel
  Syscall Interface
User Space
  Sandbox          <--- introduce this for security
    /--------------\
    | Libraries    |
    | Applications |
    \--------------/
```

### Contact Linux Kernel from Container

Run syscall from within a pod container:

```
# uname() syscall
uname -r

# check syscalls
strace uname -r
```

Further reading:

- kernel exploit "Dirty COW" (CVE-2016-5195):
  https://en.wikipedia.org/wiki/Dirty_COW

### Open Container Initiative OCI

- Linux Foundation project to design open standards for virtualization
- maintain specification for runtime, image, distibution
- maintain runtime "runc"

dockerInc/docker -> moby-> containerd -> oci/runc -> libcontainer

early days: kubelet -> dockershim -> dockerd -> containerd -> runc

nowadays: use CRI container runtime interface allows for any of

- dockershim -> dockerd -> containerd -> runc
- cri-containerd -> containerd -> runc
- cri-o -> runc
- containerd -> shim API (kata, firecracker, gVisor)
- sinularity-cri -> singularity

can be set using `kubelet --container-runtime and --container-runtime-endpoint`

### Kata Containers

For every container

- additional isolation with a lightweight VM and individual private kernels
- strong separation layer
- hypervisor/VM-based
- all managed by kata
- QEMU as defaulti

-> needs nested virtualisation in cloud!

### gVisor

user-space kernel for containers by Google. - wait what? :D

- another layer of separation
- NOT hypervisor-based
- simulates kernel syscalls in GoLang with limited functionality
- runs in userspace separated from linux kernel
- runtime is called `runsc`

App -> SysCalls -> gVisor -> limited SysCalls -> Host Kernel -> Hardware

Effectively filters out unwanted syscalls.

Create a RuntimeClass:
https://kubernetes.io/docs/concepts/containers/runtime-class/

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

Let pod use this RuntimeClass (will be pending untill runsc is installed and
available on node):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gvisor
spec:
  runtimeClassName: gvisor
  containers:
    - image: nginx
      name: pod
```

Configure containerd to use both, runc and runsc (gvisor), by choice:

- Download and run this script
  (if required replace URL with latest version of gvisor)
  ```
  bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/course-content/microservice-vulnerabilities/container-runtimes/gvisor/install_gvisor.sh)
  ```

Check kernel in pod/container:

```
k exec -it pod -- bash

> uname -r
4.4.0

> dmesg
[    0.000000] Starting gVisor...
[    0.514130] Digging up root...
[    0.824506] Waiting for children...
[    1.065813] Searching for socket adapter...
[    1.113365] Conjuring /dev/null black hole...
[    1.153509] Searching for needles in stacks...
[    1.487050] Granting licence to kill(2)...
[    1.888209] Synthesizing system calls...
[    2.293755] Creating process schedule...
[    2.356807] Verifying that no non-zero bytes made their way into /dev/zero...
[    2.476935] Checking naughty and nice process list...
[    2.908415] Ready!
```

### Further Reading

- Container Runtime Landscape
  https://www.youtube.com/watch?v=RyXL1zOa8Bw
- Gvisor
  https://www.youtube.com/watch?v=kxUZ4lVFuVo
- Kata Containers
  https://www.youtube.com/watch?v=4gmLXyMeYWI

## 18. OS Level Security Domains

### Security Contexts

- https://kubernetes.io/docs/concepts/security/pod-security-standards/
- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#podsecuritycontext-v1-core

Defines privilege and access control for pods/containers:

- userID / groupID / fsGroup
- privileged vs unprivileged
- Linux capabilities

On K8s by default: root:root

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
    - name: sec-ctx-vol
      emptyDir: {}
  containers:
    - name: sec-ctx-demo
      image: busybox:1.28
      command: ["sh", "-c", "sleep 1h"]
      volumeMounts:
        - name: sec-ctx-vol
          mountPath: /data/demo
      securityContext:
        allowPrivilegeEscalation: false
```

There is also `runAsNonRoot`, check:
https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#securitycontext-v1-core

### Privileged Containers

Privileged means container user 0 (root) is directly mapped to host user 0
(root).

Check in unprivileged container:

```
> sysctl kernel.hostname=cks-master
sysctl: error setting key 'kernel.hostname': Read-only file system
```

Whereas in privileged mode (securityContext.privileged=true):

```
> sysctl kernel.hostname=cks-master
kernel.hostname = cks-master
```

### Privilege Escalation

By default allowed in k8s:
spec.securityContext.allowPrivilegeEscalation=true

What does escalation mean?
Process can gain more privileges than its parent process.

Verify for default setting:

```
> cat /proc/1/status | grep -i nonew
NoNewPrivs: 0
```

Verify for `spec.securityContext.allowPrivilegeEscalation=false`:

```
> grep -i nonew /proc/1/status
NoNewPrivs:	1
```

## 19. Mutual TLS

Two-way (bilateral) authentication = two parties authenticating each other at
the same time.

Common situation:

- Request -> https -> Ingress + TLS termination -> decrypted traffic within cluster
- if attacker gains access to cluster, they can read inter-pod traffic

With mTLS every pod can encrypt and decrypt traffic to other pods.

- need CA
- need client & server cert for each pod
- want auto-rotate certs

For k8s mTLS is implemented via Service Meshes using proxy sidecars.

- proxy container is managed externally (e.g. Istio, LinkerD...)
- app containers do not need to be touched
- realized via initContainers that create IPtable entries to route traffic
  through proxy; needs `NET_ADMIN` capability

Further reading:

- Demystifying Istio's sidecar injection model by Manish Chugtu
  https://istio.io/v1.14/blog/2019/data-plane-setup/

# OPA

## 20. OPA

### Introduction

> "The Open Policy Agent (OPA) is an open source, general-purpose policy engine
> that enables unified, context-aware policy enforcement across the entire
> stack."

Request Workflow: authentication -> authorization -> admission control

- not kubernetes-specific
- does not know concepts like pods or deployments
- "OPA Gatekeeper" will make use of admission controllers -> CRDs
- CRDs work with ConstraintTemplates and Constraints
- implementation of policies using rego language
- works with JSON/YAML

### Install OPA

NOTE: in production, one would use helm to install all components from vendor:

- https://github.com/open-policy-agent/gatekeeper
- https://open-policy-agent.github.io/gatekeeper/website/docs/install/

Make sure no other admission plugins than NodeRestriction are enabled in
apiserver manifest.

NOTE: we will use the official latest OPA gatekeeper manifests instead of the outdated ones provided by KillerShell.

```
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml
```

This will amonst others install a validating admission webhook configuration.

- Check this for more details on dynamic admission control:
  https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
- validating vs mutating admission webhooks:
  validate vs altering resources (like e.g. auto-scaling)

Check new CRDs:

```
> k get crd | grep gate
configs.config.gatekeeper.sh
constraintpodstatuses.status.gatekeeper.sh
constrainttemplatepodstatuses.status.gatekeeper.sh
constrainttemplates.templates.gatekeeper.sh
```

> NOTE:
> KillerShell uses old versions of gatekeeper where apiVersion was still
> v1beta1. we need v1. Check examples here:
> https://github.com/open-policy-agent/gatekeeper/blob/master/demo/basic/templates/k8srequiredlabels_template.yaml
> .
> CRD also needs to be "structural" now, so we need some additional fields, see
> https://kubernetes.io/blog/2019/06/20/crd-structural-schema/

### Example 1: Deny-all policy

```yaml
apiVersion: templates.gatekeeper.sh/v1 # <- not beta anymore!
kind: ConstraintTemplate
metadata:
  name: k8salwaysdeny
spec:
  crd:
    spec:
      names:
        kind: K8sAlwaysDeny # <-- this will be created as new custom resource
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object # <- needed b/c of "structural schema" requirement
          properties:
            message:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8salwaysdeny

        violation[{"msg": msg}] {
          1 > 0
          msg := input.parameters.message
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1 # <- this is still v1beta1!
kind: K8sAlwaysDeny
metadata:
  name: pod-always-deny
spec:
  # good for testing: will not reject new creations, only gather violations
  # enforcementAction: dryrun
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    message: "ACCESS DENIED!"
```

```
k get crd
k get constrainttemplate
k get k8salwaysdeny # <- show number of violations
k describe k8salwaysdeny # <- shows details on violations
k run pod --image nginx # <- will be denied
```

Important Notes:

- new constraints will only deny creation of new resources, not delete
  already existing ones. Violations are counted for existing ones as well though.
- able to see which of the running pods would be affected.

- in order to throw a violation, all conditions in the rego block must be true
- after altering a template, gatekeeper controller manager will take care of
  updating all derived constraints

### Example 2: Enforce namespace labels

original source:
https://github.com/open-policy-agent/gatekeeper/blob/master/demo/basic/templates/k8srequiredlabels_template.yaml

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("you must provide labels: %v", [missing])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: pod-must-have-cks
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    labels: ["cks"]
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-cks
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["cks"]
```

### Example: Enforce Replica Count in Deployments

source:
https://github.com/killer-sh/cks-course-environment/blob/master/course-content/opa/deployment-replica-count/k8sminreplicacount_template.yaml

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sminreplicacount
spec:
  crd:
    spec:
      names:
        kind: K8sMinReplicaCount
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            min:
              type: integer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sminreplicacount

        violation[{"msg": msg, "details": {"missing_replicas": missing}}] {
          provided := input.review.object.spec.replicas
          required := input.parameters.min
          missing := required - provided
          missing > 0
          msg := sprintf("you must provide %v more replicas", [missing])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sMinReplicaCount
metadata:
  name: deployment-must-have-min-replicas
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
  parameters:
    min: 2
```

### Rego playground & Further Reading

Rego playground:
https://play.openpolicyagent.org

Policy Examples:
https://github.com/BouweCeunen/gatekeeper-policies

Official examples:
https://open-policy-agent.github.io/gatekeeper/website/docs/examples

Nice article:
https://dustinspecker.com/posts/open-policy-agent-introduction-gatekeeper/

Talk:
Policing Your K8s Clusters with OPA
https://www.youtube.com/watch?v=RDWndems-sk

# Supply Chain Security

## 21. Image Footprint

### Reduce Image Size

VM vs Container - consider inverse direction this time:

- Container: kernel can access app process
- VM: kernel has no access to guest processes

- Docker cotainers constructed as layers
- "From" statement imports usually multiple layers

NOTE:

> Only the instructions RUN, COPY and ADD create layers. Other instructions
> create intermediate images, and do not increase the size of the build.

How to reduce image footprint? -> Multi-Stage Builds

```
# -> procudes ~900 MB image
FROM ubuntu
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y golang-go
COPY app.go .
RUN CGO_ENABLED=0 go build app.go
CMD ["./app"]
```

vs.

```
# -> procudes ~9 MB image
# stage zero
FROM ubuntu
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y golang-go
COPY app.go .
RUN CGO_ENABLED=0 go build app.go

# stage one
FROM alpine
# copy from stage zero
COPY --from=0 /app .
CMD ["./app"]
```

### Securing and Hardening

Best-practices:

- for reliability: Use specific application/image versions instead of "latest"
- use 3rd party tools to check base images
- don't run as root
- make filesystem read-only
- remove shell access

```
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y golang-go
COPY app.go .
RUN CGO_ENABLED=0 go build app.go

FROM alpine
RUN chmod a-w /etc # and others...
RUN addgroup -S appgroup && adduser -S appuser -G appgroup -h /home/appuser
RUN rm -rf /bin/*
COPY --from=0 /app /home/appuser
USER appuser
CMD ["/home/appuser/app"]
```

### Further Reading

Docker best practices:
https://docs.docker.com/develop/develop-images/dockerfile_best-practices

## 22. Static Analysis

### Overview

Check source code and text files against rules and enforces them.

Examples:

- always define resources requests & limits
- pods should never use default ServiceAccount

CI/CD: code -> commit -> build -> test -> deploy <br>
Analysis: ^......^........^........^.......^

Where to check?

- code: IDE integrations
- commit: check code before/after committing using git-hooks
- build: check Dockerfiles
- test/deploy: PSP/OPA

Tools:

- kubesec
- OPA
- Neuvector

### Kubesec

kubesec.io

- opensource security risk analysis for k8s resources
- score-based
- opinionated! - fixed set of rules acc. to security best practices
- run as:
  - binary
  - docker container
  - kubectl plugin
  - admission controller (kubesec-webhook)

```
k run nginx --image nginx -oyaml --dry-run=client > pod.yaml
docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < pod.yaml
```

```json
[
  {
    "object": "Pod/nginx.default",
    "valid": true,
    "message": "Passed with a score of 0 points",
    "score": 0,
    "scoring": {
      "advise": [
        {
          "selector": "containers[] .securityContext .readOnlyRootFilesystem == true",
          "reason": "An immutable root filesystem can prevent malicious binaries being added to PATH and increase attack cost"
        },
        {
          "selector": "containers[] .securityContext .runAsNonRoot == true",
          "reason": "Force the running image to run as a non-root user to ensure le
ast privilege"
        },
        {
          "selector": "containers[] .securityContext .runAsUser -gt 10000",
          "reason": "Run as a high-UID user to avoid conflicts with the host's user table"
        },
        {
          "selector": "containers[] .securityContext .capabilities .drop",
          "reason": "Reducing kernel capabilities available to a container limits its attack surface"
        },
        {
          "selector": "containers[] .securityContext .capabilities .drop | index(\"ALL\")",
          "reason": "Drop all capabilities and add only those required to reduce syscall attack surface"
        },
        {
          "selector": ".spec .serviceAccountName",
          "reason": "Service accounts restrict Kubernetes API access and should be configured with least privilege"
        },
        {
          "selector": "containers[] .resources .requests .cpu",
          "reason": "Enforcing CPU requests aids a fair balancing of resources across the cluster"
        },
        {
          "selector": "containers[] .resources .limits .cpu",
          "reason": "Enforcing CPU limits prevents DOS via resource exhaustion"
        },
        {
          "selector": "containers[] .resources .requests .memory",
          "reason": "Enforcing memory requests aids a fair balancing of resources across the cluster"
        },
        {
          "selector": "containers[] .resources .limits .memory",
          "reason": "Enforcing memory limits prevents DOS via resource exhaustion"
        },
        {
          "selector": ".metadata .annotations .\"container.seccomp.security.alpha.kubernetes.io/pod\"",
          "reason": "Seccomp profiles set minimum privilege and secure against unknown threats"
        },
        {
          "selector": ".metadata .annotations .\"container.apparmor.security.beta.kubernetes.io/nginx\"",
          "reason": "Well defined AppArmor policies may provide greater protection from unknown threats. WARNING: NOT PRODUCTION READY"
        }
      ]
    }
  }
]
```

### OPA Conftest

- unit-test framework for K8s configurations
- Rego language based

```
git clone https://github.com/killer-sh/cks-course-environment.git
cd cks-course-environment/course-content/supply-chain-security/static-analysis/conftest/kubernetes
./run.sh
```

Rego example policies:

```
# from https://www.conftest.dev
package main

deny[msg] {
  input.kind = "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot = true
  msg = "Containers must not run as root"
}

deny[msg] {
  input.kind = "Deployment"
  not input.spec.selector.matchLabels.app
  msg = "Containers must provide app label for pod selectors"
}
```

## 23. Image Vulnerability

Vulnerability targets:

- remotely accessible apps in containers
- local apps inside container
- all dependencies

Databases:

- https://cve.mitre.org
- https://nvd.nist.gov

Image scanning

- check during build
- check at runtime
- enforce e.g. certain registries via PSP/OPA

When to check?

CI/CD pipeline:

code -> commit -> build -> test -> deploy <br>
..^.................^................^ <br>
..|.................|................| <br>
static anal. registry (external) OPA etc. <br>

K8s:

API HTTP hander -> Author./Authent. -> Mutating Admission -> Object Schema Validation -> Validation Admission -> ETCD
-> mutating /validating webhooks

### Tools

Clair

- open source
- static analysis of vulnerabilities in app containers
- ingests vulnerability metadata from configured set of sources (CVE databases)
- provides API
- a bit complex to set up

Trivy

- open source
- "Simple and Comprehensive Vulnerability Scanner for Containers and other
  Artifacts, Suitable for CI"
- simple, easy, fast
- one-command run

```
# https://github.com/aquasecurity/trivy#docker
docker run ghcr.io/aquasecurity/trivy:latest image nginx:latest
```

Check for multiple CVEs on system-installed trivy:

```
# grep image
k get deploy -n infra -o wide

# use regex OR
trivy httpd:2.4.39-alpine | grep -E "CVE-2021-28831|CVE-2016-9841"
```

## 24. Secure Supply Chain

### Image Reference

Supply Chain:
Tools -> Software Development -> [ Container -> CI/CD Registry -> k8s Cloud ] -> Browser

- private Registries with Docker: `docker login`
- private Registries with K8s: secret of type docker-registry + serviceAccount

Which registries are used by default?

```
k get pod -A -oyaml | grep "image:" | uniq
```

- docker.io
- quay.io
- registry.k8s.io

Check apiserver in more detail:

```
> k -n kube-system get pod kube-apiserver-cks-master -o yaml
[...]
  containerStatuses:
  - containerID: containerd://e083298d71974439f28de28b7d56f715a9adb165e3ae560fac63d5f6a628ce2f
    image: registry.k8s.io/kube-apiserver:v1.28.2
    imageID: registry.k8s.io/kube-apiserver@sha256:6beea2e5531a0606613594fd3ed92d71bbdcef99dd3237522049a0b32cad736c
[...]
```

Convenience command to check pod images of a specific deployment

```
k get pod -l app=crazy-deployment -oyaml | grep image:
```

- tags can be overwritten! -> not a 100% secure reference
- digest in form of sha256 sum are immutable for a specific image

Further reading:

- https://cloud.google.com/kubernetes-engine/docs/tutorials/using-container-image-digests-in-kubernetes-manifests
- https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy

### Whitelisting using OPA

policy to only allow docker.io and k8s.gcr.io

```
# install opa
kubectl create -f https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/course-content/opa/gatekeeper.yaml

# opa resources
https://github.com/killer-sh/cks-course-environment/tree/master/course-content/supply-chain-security/secure-the-supply-chain/whitelist-registries/opa
```

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8strustedimages
spec:
  crd:
    spec:
      names:
        kind: K8sTrustedImages
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8strustedimages

        violation[{"msg": msg}] {
          image := input.review.object.spec.containers[_].image
          not startswith(image, "docker.io/")
          not startswith(image, "k8s.gcr.io/")
          msg := "not trusted image!"
        }
```

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sTrustedImages
metadata:
  name: pod-trusted-images
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

### ImagePolicyWebhook

- api request -> apiserver -> allow/deny
- validation @ apiserver: AdmissionControllers <-> ImagePolicyWebhook <-> External Service
- external Service receives "ImageReview" object

Enable in apiserver yaml:

```
--enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
--admission-control-config-file=/etc/kubernetes/admission/admission_config.yaml
```

Add configuration from CKS repo:

```
# get example
git clone https://github.com/killer-sh/cks-course-environment.git
cp -r cks-course-environment/course-content/supply-chain-security/secure-the-supply-chain/whitelist-registries/ImagePolicyWebhook/ /etc/kubernetes/admission

# to debug the apiserver we check logs in:
/var/log/pods/kube-system_kube-apiserver*

# example of an external service which can be used
https://github.com/flavio/kube-image-bouncer
```

NOTE:
Registering the pugin consists of:

- adding to the admission plugin list
- adding volume mounts
- adding the config path which contains the...
  - ...admission config file pointing to...
  - ...kubeconfig file that in turn uses...
  - ...certificates and points to the external service

needs to point to / include a kubeconfig

Example admission and kubeconf:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ImagePolicyWebhook
    configuration:
      imagePolicy:
        kubeConfigFile: /etc/kubernetes/admission/kubeconf
        allowTTL: 50
        denyTTL: 50
        retryBackoff: 500
        defaultAllow: true
```

```yaml
apiVersion: v1
kind: Config

# clusters refers to the remote service.
clusters:
  - cluster:
      certificate-authority: /etc/kubernetes/admission/external-cert.pem # CA for verifying the remote service.
      server: https://external-service:1234/check-image # URL of remote service to query. Must use 'https'.
    name: image-checker

contexts:
  - context:
      cluster: image-checker
      user: api-server
    name: image-checker
current-context: image-checker
preferences: {}

# users refers to the API server's webhook configuration.
users:
  - name: api-server
    user:
      client-certificate: /etc/kubernetes/admission/apiserver-client-cert.pem # cert for the webhook admission controller to use
      client-key: /etc/kubernetes/admission/apiserver-client-key.pem # key matching the cert
```

# Runtime Security

## 25. Behavioral Analytics

List of syscalls: https://man7.org/linux/man-pages/man2/syscalls.2.html

### strace

- intercepts and logs syscalls made by a process
- logs and displays signals received by a process
- great for diagnostics, learning, debugging

Example:

```
> trace ls /
execve("/usr/bin/ls", ["ls"], 0x7ffd0278e3a0 /* 22 vars */) = 0
brk(NULL)

[...]

close(3)                                = 0
fstat(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "bin   dev  home  lib32\tlibx32\t  "..., 72bin   dev  home  lib32	libx32	   media  opt	root  sbin  srv  tmp  var
) = 72
write(1, "boot  etc  lib\t lib64\tlost+found"..., 68boot  etc  lib	lib64	lost+found  mnt    proc  run   snap  sys  usr
) = 68
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

Example "count and summarize" (-> which syscalls were how often made?):

```
> strace -cw ls /
bin   dev  home  lib32	libx32	   media  opt	root  sbin  srv  tmp  var
boot  etc  lib	lib64	lost+found  mnt    proc  run   snap  sys  usr
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 18.91    0.000535          13        40           mmap
 15.31    0.000433          18        24           openat
 11.03    0.000312          12        25           fstat
 10.68    0.000302          11        26           close
 10.37    0.000294         146         2           ioctl
  7.23    0.000205         204         1           execve
  5.40    0.000153          19         8           mprotect
  4.20    0.000119          13         9           read
  3.34    0.000094          47         2           getdents64
  2.87    0.000081          40         2           write
  2.57    0.000073           9         8           pread64
  1.42    0.000040          40         1           munmap
  1.36    0.000038          38         1           stat
  1.06    0.000030          14         2         2 statfs
  0.90    0.000026          12         2         2 access
  0.90    0.000025           8         3           brk
  0.54    0.000015           7         2           rt_sigaction
  0.53    0.000015           7         2         1 arch_prctl
  0.30    0.000008           8         1           prlimit64
  0.29    0.000008           8         1           futex
  0.27    0.000008           7         1           set_tid_address
  0.26    0.000007           7         1           rt_sigprocmask
  0.25    0.000007           7         1           set_robust_list
------ ----------- ----------- --------- --------- ----------------
100.00    0.002830                   165         5 total
```

### proc dir

- information and connections to processes and kernel
- study it to learn how processes work
- configuration and administrative tasks
- contains files that don't really exist, yet you can access them

use strace to investigate a certain process like ETCD using its PID:

```
ps aux | grep etcd

# -f = follow forks, -cw = count and summarize, -p = PID
# needs to be interrupted using CTRL+C
strace -p $PID -f
```

check proc folder:

```
> ls -l /proc/$PID
exe -> /usr/local/bin/etcd
fd -> contains open files

> ls -lv /proc/$PID/fd

lrwx------ 1 root root 64 Nov  6 08:19 0 -> /dev/null
l-wx------ 1 root root 64 Nov  6 08:19 1 -> 'pipe:[27639]'
l-wx------ 1 root root 64 Nov  6 08:19 2 -> 'pipe:[27640]'
lrwx------ 1 root root 64 Nov  6 08:20 3 -> 'socket:[28746]'
lrwx------ 1 root root 64 Nov  6 08:20 4 -> 'anon_inode:[eventpoll]'
lr-x------ 1 root root 64 Nov  6 08:19 5 -> 'pipe:[28747]'
l-wx------ 1 root root 64 Nov  6 08:19 6 -> 'pipe:[28747]'
lrwx------ 1 root root 64 Nov  6 08:19 7 -> 'socket:[28750]'
lrwx------ 1 root root 64 Nov  6 08:19 8 -> 'socket:[29738]'
lrwx------ 1 root root 64 Nov  6 08:19 9 -> 'socket:[29739]'
lrwx------ 1 root root 64 Nov  6 08:19 10 -> /var/lib/etcd/member/snap/db
lrwx------ 1 root root 64 Nov  6 08:20 11 -> /var/lib/etcd/member/wal/0000000000000001-0000000000015f14.wal
lr-x------ 1 root root 64 Nov  6 08:20 12 -> /var/lib/etcd/member/wal
l-wx------ 1 root root 64 Nov  6 08:20 13 -> /var/lib/etcd/member/wal/0.tmp
lrwx------ 1 root root 64 Nov  6 08:20 14 -> 'socket:[29751]'
lrwx------ 1 root root 64 Nov  6 08:20 18 -> 'socket:[28782]'
lrwx------ 1 root root 64 Nov  6 08:20 19 -> 'socket:[29761]'
lrwx------ 1 root root 64 Nov  6 08:20 20 -> 'socket:[29762]'
lrwx------ 1 root root 64 Nov  6 08:20 21 -> 'socket:[29763]'
```

Entry `snap/db` looks pretty much like a DB. Let's check:

```
> ls /var/lib/etcd/member/snap/db
[binary output]
```

Convert binary to text using `strings` and try to extract a secret:
(in this case, encryption at rest was activated!)

```
> k create secret generic credit-card --from-literal cc=11223344
> cat /var/lib/etcd/member/snap/db | strings | grep credit-card -A10 -B10

Update
coordination.k8s.io/v1"
FieldsV1:
{"f:metadata":{"f:labels":{".":{},"f:apiserver.kubernetes.io/identity":{},"f:kubernetes.io/hostname":{}}},"f:spec":{"f:holderIdentity":{},"f:leaseDurationSeconds":{},"f:renewTime":{}}}B
Iapiserver-dbwliaqnbjndmefkqorqizdkz4_6058fccf-e3b8-44ea-843b-7d7fbfbb1b11
%/registry/secrets/default/credit-card
k8s:enc:aescbc:v1:key:M
|Zwn
 Rl(
KGS#
<k<{
```

Without encryption at rest it would look like this:

```
> k create secret generic secret123 --from-literal pass=12345678
> cat /var/lib/etcd/member/snap/db | strings | grep credit-card -A15

!/registry/secrets/default/secret123
Secret
secret123
default"
*$b5572183-d7e3-4611-a68a-95caa9038bf82
kubectl-create
Update
FieldsV1:-
+{"f:data":{".":{},"f:pass":{}},"f:type":{}}B
pass
12345678
Opaque
```

### Extract secret from pod ENV

Create a httpd pod with an arbitrary "secret" env.

Find the corresponding process ID on worker node
-> might be difficult because of subprocesses.
-> use `pstree` and find ID of "root process", i.e. the first one spawned by
containerd-shim (here: 1037794)

```
> crictl inspect 4b080eba1fcf0 | jq ".info.pid"

# OR
> pstree -p
[...]
           │                       ├─{containerd-shim}(2484)
           │                       ├─{containerd-shim}(44699)
           │                       └─{containerd-shim}(591161)
           ├─containerd-shim(1037728)─┬─httpd(1037794)─┬─httpd(1037807)─┬─{httpd}(1037811)
           │                          │                │                ├─{httpd}(1037812)
           │                          │                │                ├─{httpd}(1037813)
           │                          │                │                ├─{httpd}(1037814)
[...]
```

Extract secret:

```
cd /proc/PID
cat environ | strings
```

-> Secrets can be extracted on hosts even without crictl or etcd installed!
We only need access to the ETCD DB file or the `/proc` directory!

### Use Falco to find malicious processes in containers

Falco by sysdig: https://falco.org/

- cloud-native runtime security (CNCF)
- ACCESS
  - Deep kernel tracing built on the Linux kernel
- ASSERT
  - describe security rules against a system (+default ones)
  - detect unwanted behavior
- ACTION
  - auto-respond to a security violation

Installation:
(official source: https://falco.org/docs/install-operate/installation/)

```
curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y
apt-get install -y linux-headers-$(uname -r)
apt-get install -y falco=0.32.1

# NOTE: I also had to manually start the service
systemctl start falco.service
```

Main configuration and default rules in `/etc/falco`

By default, falco:

- logs to syslog
- syscall event drops

Check falco output:

```
# either via file
tail -f /var/log/syslog | grep falco

# or one-shot via service
systemctl status falco.service

# or following via service
journalctl --follow -u falco.service
```

And create an interactive shell session while watching falco:

```
> k exec -it $POD -- bash

| Nov 09 09:40:45 cks-worker falco[1057213]: 09:40:45.465693254: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 apache (id=4b080eba1fcf) shell=bash parent=runc cmdline=bash terminal=34816 container_id=4b080eba1fcf image=docker.io/library/>
| Nov 09 09:42:29 cks-worker falco[1057213]: 09:42:29.211379652: Notice User management binary command run outside of container (user=root user_loginuid=-1 command=groupadd google-sudoers parent=google_guest_ag gparent=systemd ggparent=<NA> gggparent=<NA>)
```

```
> [in container] echo user >> /etc/passwd
| Nov 09 09:45:45 cks-worker falco[1057213]: 09:45:45.720167659: Error File below /etc opened for writing (user=root user_loginuid=-1 command=bash parent=<NA> pcmdline=<NA> file=/etc/passwd program=bash gparent=<NA> ggparent=<NA> gggparent=<NA> container_id=4b080eba1fcf image=docker.io/>
```

### Example Falco configuration

Example Falco rule as listed in `/etc/falco/falco_rules.yaml`:

```
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal (user=%user.name user_loginuid=%user.loginuid %container.info
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [container, shell, mitre_execution]
```

There are also default K8s audit rules, either as "rules" or as "macros" in
`/etc/falco/k8s_audit_rules.yaml`:

```
- macro: sensitive_vol_mount
  condition: >
    (ka.req.pod.volumes.hostpath intersects (/proc, /var/run/docker.sock, /, /etc, /root, /var/run/crio/crio.sock, /home/admin, /var/lib/kubelet, /var/lib/kubelet/pki, /etc/kubernetes, /etc/kubernetes/manifests))

- rule: Create Sensitive Mount Pod
  desc: >
    Detect an attempt to start a pod with a volume from a sensitive host directory (i.e. /proc).
    Exceptions are made for known trusted images.
  condition: kevt and pod and kcreate and sensitive_vol_mount and not ka.req.pod.containers.image.repository in (falco_sensitive_mount_images)
  output: Pod started with sensitive mount (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image volumes=%jevt.value[/requestObject/spec/volumes])
  priority: WARNING
  source: k8s_audit
  tags: [k8s]
```

Check supported fields here (Docs -> Reference -> Falco Rules)
https://falco.org/docs/rules/supported-fields

### Change Falco Rule

Rule overrides go into `/etc/falco/falco_rules.local.yaml`.

NOTE: falco service does not have to be restarted for changes to take effect!

```
Rule: "A shell was spawned in a container with an attached terminal"
Output Format: TIME,USER-NAME,CONTAINER-NAME,CONTAINER-ID
Priority: WARNING
```

Check supported fields here (Docs -> Reference -> Falco Rules)
https://falco.org/docs/rules/supported-fields

```
output: >
  %evt.time, %user.name, %container.name, %container.id
```

### Further reading

- https://sysdig.com/blog/oss-container-security-runtime/
- https://sysdig.com/blog/container-security-docker-image-scanning/
- Syscall talk by Liz Rice: https://www.youtube.com/watch?v=8g-NUUmCeGI

## 26. Immutability of Containers at Runtime

### Container Immutability

> Immutability = A container won't be modified during its lifetime.

Mutability examples:

- ssh on VM|Container instance
- stop / update / restart application

Very common process few years ago.

Immutable version:

- create new VM|Container image
- delete VM|Container instance
- create new VM|Container instance

-> we always know the state!

Benefits:

- advanced deployment methods (e.g. the ones that come with K8s)
- easy rollback
- more reliability
- better security (at least on container level)

### Ways to enforce Immutability

Hardening at container level:

- remove shell binaries
- make file system read-only
- run as user and non-root

But...

- If we have no control over image? -> use as base image and post-harden it
- If we have no control over the container at all or are too lazy?

Hardening at Kubernetes level:

Pod Startup timeline:
pod starts -> [init container] -> app container starts -> app container runs "command"

- [bad] override command with custom hardening script
- [bad] abuse startupProbes and let it do changes
- [good] enforce non-root and RO-filesystem via securityContexts and PodSecurityPolicies
- [good] move logic to InitContainers
- [good] RBAC to ensure only certain people can even edit pod specs

### Example: StartupProbe

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: immutable
spec:
  containers:
    - image: httpd
      name: immutable
      startupProbe:
        exec:
          command:
            - rm
            - /bin/bash
        initialDelaySeconds: 5
        periodSeconds: 2
        failureThreshold: 2
```

> NOTE:
> Logs from startupProbes are only visible in k8s events, not in container logs!

### Example: SecurityContext for RO file system

Plainly enforcing read-only-ness will mostly not work, because containers
often want to write logs or at least a PID file.

Solution: combine securityContext with emptyDir volumes

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: immutable
  name: immutable
spec:
  containers:
    - image: httpd
      name: immutable
      securityContext:
        readOnlyRootFilesystem: true
      volumeMounts:
        - mountPath: /usr/local/apache2/logs
          name: empty
  volumes:
    - name: empty
      emptyDir:
        sizeLimit: 500Mi
```

This is conceptionally equivalent to this docker command:

with

```
docker run --read-only --tmpfs /run my-container
```

## 27. Auditing

All API requests can be logged in audit logs incl. metadata!

Why do we need them?

- did someone access a secret while it was not properly protected?
- when did user X access cluster Y last time?
- does my CRD work properly?

We can decide: how much and what exactly should be logged via Audit Policy Stages

Stages:

1. RequestReceived
   - The stage for events generated as soon as the audit handler receives the
     request, and before it is delegated down the handler chain.
2. ResponseStarted
   - Once the response headers are sent, but before the response body is sent.
     This stage is only generated for long-running requests (e.g. `watch`).
3. ResponseComplete
   - The response body has been completed and no more bytes will be sent.
4. Panic
   - Events generated when a panic occurred.

Levels:

0. None
   - don't log events that match this rule.
1. Metadata
   - log request metadata (requesting user, timestamp, resource, verb, etc.) but
     not request or response body.
2. Request
   - log event metadata and request body but not response body. This does not
     apply for non-resource requests.
3. RequestResponse
   - log event metadata, request and response bodies. This does not apply for
     non-resource requests.

Things to consider: many api requests -> much data to store!

### Audit Policies

The FIRST matching rule sets the audit level of an event, so order is important!

Example 1: Simple "Everything"

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
```

Example 2:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"

rules:
  # log no "read" actions
  - level: None
    verbs: ["get", "watch", "list"]

  # log nothing regarding events
  - level: None
    resources:
      - group: "" # core
        resources: ["events"]

  # log nothing coming from some groups
  - level: None
    userGroups: ["system:nodes"]

  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]

  # for everything else log
  - level: Metadata
```

Note:
This would log for secrets not only the API requests, but also the response
which includes the entire body, i.e. the secret data itself. This should be
considered when sending audit logs to an external service.

### Audit Backends

Backends:

- JSON files <-- important format for CKS Cert
- webhook (external API)
- dynamic backend (AuditSink API)\*\*

\*\* UPDATE: This feature has been dropped in alpha state as of v1.19, see here:
https://dev.bitolog.com/the-death-of-kubernetes-auditsink/

External Services: ElasticSearch - FileBeat - FluentD

### Enable Auditing

https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/

Create path

```
mkdir /etc/kubernetes/audit
```

Adapt kube-apiserver manifest and make sure mount path is not read-only!

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml       # add
    - --audit-log-path=/etc/kubernetes/audit/logs/audit.log       # add
    - --audit-log-maxsize=500                                     # add
    - --audit-log-maxbackup=5                                     # add

[...]

    volumeMounts:
    - mountPath: /etc/kubernetes/audit      # add
      name: audit                           # add

  volumes:
  - hostPath:                               # add
      path: /etc/kubernetes/audit           # add
      type: DirectoryOrCreate               # add
    name: audit                             # add
```

For the webhook backend, it would be

```
--audit-webhook-config-file
--audit-webhook-initial-backoff
```

### Check audit logs for secrets

```
k create secret generic very-secure --from-literal user=admin
cat /etc/kubernets/audit/logs/audit.log | grep very-secure
```

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "de8d1ef7-5068-4f30-9e26-eeaf960da810",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/secrets?fieldManager=kubectl-create\u0026fieldValidation=Strict",
  "verb": "create",
  "user": {
    "username": "kubernetes-admin",
    "groups": ["system:masters", "system:authenticated"]
  },
  "sourceIPs": ["10.156.0.4"],
  "userAgent": "kubectl/v1.28.2 (linux/amd64) kubernetes/89a4ea3",
  "objectRef": {
    "resource": "secrets",
    "namespace": "default",
    "name": "very-secure",
    "apiVersion": "v1"
  },
  "responseStatus": { "metadata": {}, "code": 201 },
  "requestReceivedTimestamp": "2023-11-10T09:12:48.114265Z",
  "stageTimestamp": "2023-11-10T09:12:48.132915Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": "",
    "mutation.webhook.admission.k8s.io/round_0_index_0": "{\"configuration\":\"gatekeeper-mutating-webhook-configuration\",\"webhook\":\"mutation.gatekeeper.sh\",\"mutated\":false}"
  }
}
```

### Restrict / Customize Audit logs

Policy should contain:

- nothing from stage RequestReceived
- nothing from "get", "watch", "list"
- from secrets only metadata level
- everything else RequestResponse level

1. Change policy file
2. Disable audit logging in apiserver & wait until restart
3. Enable audit logging again & wait until restart
   - If apiserver does not restart, check
     `/var/log/pods/kube-system_kube-apiserver*`
4. Test new changes

```yaml
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  - level: None
    verbs: ["get", "watch", "list"]

  # Log secret changes only at the Metadata level.
  - level: Metadata
    resources:
      - group: "" # core API group
        resources: ["secrets"]

  # Catch-all: Log all other resources at the Request level.
  - level: RequestResponse
```

### Further Reading

Auditing in K8s 101: Nikhita Raghunath, Loodse:
https://www.youtube.com/watch?v=HXtLTxo30SY

# System Hardening

## 28. Kernel Hardening Tools

### Container Isolation

1. Namespaces restrict what processes can see
   - other processes
   - users
   - filesystem
2. cgroups restrict the resource usage of processes
   - RAM
   - CPU
   - disk space
3. kernel vs user space; syscall interface

Kernel hardening:
Every process can communicate directly with syscall interface.
-> restrict using AppArmor or seccomp
-> sit between user and kernel space and is considered part of kernel space

> NOTE:
> AppArmor is used by Linux distributions like Ubuntu, SUSE, Arch etc., while
> SELinux is used by RHEL and its derivatives.

What's the difference between AppArmor/seccomp and tools like gVisor/kata?
-> host kernel hardening vs container runtime sandboxes with "user-space kernel
emulations"

BTW, there's also firejail that runs in user space and utilizes Linux
namespaces.

### AppArmor

AppArmor profiles define what processes like firefox etc. may or may not do.

Modes:

- unconfined: process can escape, nothing is enforced
- complain: process can escape but incidents will be logged
- enforce: process cannot escape

Important commands:

```bash
# show all profiles
aa-status

# generate a new profile (smart wrapper around aa-logprof)
aa-genprof

# put profile in complain mode
aa-complain

# put profile in enforce mode
aa-enforce

# update the profile if app produced some more usage logs (syslog)
```

NOTE: if commands are not available on Ubuntu, install `apparmor-utils` package

### Create Profile for curl

Test curl before:

```
> curl ifconfig.me
OUTPUT = current IP
```

Generate profile for curl:

```
aa-genprof curl
> choose (F)inish
```

Test curl again:

```
> curl ifconfig.me
curl: (6) Could not resolve host: ifconfig.me
```

`/usr/bin/curl` is now also listed in

```
aa-status
```

Profiles are located in `/etc/apparmor.d/`, e.g. `/etc/apparmor.d/usr.bin.curl`.

Auto-update profile for curl using generated syslogs:

> NOTE:
> On my ubuntu instance, I received a seg fault/core dumped using this command.
> Solution: app-armor main package was outdated -> simply upgrade into a
> consistent state.

```
> aa-logprof

Reading log entries from /var/log/syslog.
Updating AppArmor profiles in /etc/apparmor.d.
Enforce-mode changes:

Profile:  /usr/bin/curl
Path:     /etc/ssl/openssl.cnf
New Mode: owner r
Severity: 2

 [1 - #include <abstractions/openssl>]
  2 - #include <abstractions/ssl_keys>
  3 - owner /etc/ssl/openssl.cnf r,
(A)llow / [(D)eny] / (I)gnore / (G)lob / Glob with (E)xtension / (N)ew / Audi(t) / (O)wner permissions off / Abo(r)t / (F)inish
```

Test curl again:

```
> curl ifconfig.me
OUTPUT = current IP
```

### AppArmor for Docker Containers

Download example profile here:
https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/course-content/system-hardening/kernel-hardening-tools/apparmor/profile-docker-nginx

Install it as file `/etc/apparmor.d/docker-nginx`, then run:

```
apparmor_parser /etc/apparmor.d/docker-nginx

# check loaded profiles
aa-status
```

-> docker-nginx is listed, but there is also a docker-default!

Run nginx in docker:

```
# starts w/o errors
docker run nginx

# will complain but still run
docker run --security-opt apparmor=docker-default nginx
> /docker-entrypoint.sh: 13: cannot create /dev/null: Permission denied
> /docker-entrypoint.sh: No files found in /docker-entrypoint.d/, skipping configuration

# run detached and try stuff in the container
docker run --security-opt apparmor=docker-default -d nginx
docker exec -it <ID> bash
> touch /root/test
```

NOTE: for deleting an AppArmor profile, you can use

```
 apparmor_parser -R /path/to/profile
```

### AppArmor for K8s containers

K8s docs: https://kubernetes.io/docs/tutorials/clusters/apparmor/#example

- container runtime needs to support AppArmor
- needs to be installed on every node
- profiles need to be available on every node
- profiles are specified per container using annotations

> NOTE:
> profile name is not the filename under `/etc/apparmor.d/` but the one
> set in the line starting with `profile`.

Annotating:
https://kubernetes.io/docs/tutorials/security/apparmor/#pod-annotation

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure
  annotations:
    container.apparmor.security.beta.kubernetes.io/secure: localhost/docker-nginx
```

Check if container really uses a profile:

```
# go to host where container is running
ssh worker-node

# find container ID
crictl ps

# check container details
crictl inspect <ID> | grep apparmor
```

### Seccomp

Secure Computing Mode

- security facility in linux kernel
- restricts execution of syscalls

- allows only specific syscalls
- if unallowed syscall is called, process is SIGKILL'd
- originally only allowed: exit(), sigreturn(), read(), write()
- nowadays often combined with BPF filters (Berkeley Packet Filter)
  - -> seccomp-bpf

### Seccomp for Docker Containers

Download seccomp profile from here:
https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/course-content/system-hardening/kernel-hardening-tools/seccomp/profile-docker-nginx.json

Safe as `default.json` and run a container using this profile:

```
docker run --security-opt seccomp=default.json nginx
```

### Seccomp for K8s Containers

> NOTE: memorize this. it's hard to find in the docs!
> Only reference is https://kubernetes.io/docs/tutorials/security/seccomp/.

Search k8s docs for kubelet argument reference.

The current argument to look for is `--root-dir` and not specific to
seccomp anymore! It defaults to `/var/lib/kubelet`.

Create a new path and move the profile there

```
mkdir /var/lib/kubelet/seccomp/profiles
```

For pod, check:
https://kubernetes.io/docs/tutorials/security/seccomp/#create-a-pod-with-a-seccomp-profile-for-syscall-auditing

> NOTE:
> Starting from v1.19, seccomp is not set via annotation anymore like AppArmor,
> but via securityContext!

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: audit-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
    - name: test-container
      image: hashicorp/http-echo:1.0
      args:
        - "-text=just made some syscalls!"
      securityContext:
        allowPrivilegeEscalation: false
```

### Further Reading

What Have Syscalls Done for you Lately?
https://www.youtube.com/watch?v=8g-NUUmCeGI

Aaron Jones: Introduction To Firejail, AppArmor, and SELinux:
https://www.youtube.com/watch?v=JFjXvIwAeVI

## 29. Reducing Attack Surface

Attack surface = everything that is exposed and can contain security risks that
could potentially be exploited by malicous code.

- Applications:
  - keep up-to-date
  - update linux kernel
  - remove unused packages
- Network
  - check and close open ports
- IAM
  - run as user, not root
  - restrict user permissions

### Host OS Footprint

- Only purpose of worker node
  - run K8s components
  - remove unnecessary services!
- Node Recycling:
  - nodes should be ephemeral
  - can be recycled any time and fast if necessary
  - nodes should be created from images

Problem with popular Linux distributions like Ubuntu, CentOS etc.:

- often include number of services
- meant to help, but widen attack surface
- the more running services, the more convenient, the larget the attack surface

Check open ports with `netstat` or `ss`:

```
ss -tulpen
netstat -tulpen
netstat -apn | grep etcd
lsof -i :22
```

Check services with `systemctl`.

Check processes with `ps`.

Example: disable snapd service

```
systemctl list-units -t service --state=running | grep snap
systemctl stop snapd
systemctl disable snapd
```

Example: investigate services

```
apt update && apt install vsftpd samba
systemctl status vsftpd.service
systemctl status smbd.service

netstat -tlpn
```

Example: disable app listening on port 21 (uses installed vsftpd service)

```
# this is the FTP server, check:
> lsof -i :21

COMMAND     PID USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
vsftpd  2663279 root    3u  IPv6 15977611      0t0  TCP *:ftp (LISTEN)
```

```
> systemctl list-units -t service | grep ftp
vsftpd.service             loaded active running vsftpd FTP server

> systemctl stop vsftpd
> systemctl disable vsftpd
```

Example: find arbitrary process listening on port 1234 and delete its binary

```
> lsof -i 1234
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
app1    23204 root    3u  IPv4  82581      0t0  TCP *:1234 (LISTEN)

> ls -l /proc/23204/exe
lrwxrwxrwx 1 root root 0 Nov 10 18:51 /proc/23204/exe -> /usr/bin/app1

> kill 23204 && rm /usr/bin/app1
```

### Linux Users

Which user currently running?

```
> whoami
root
```

Check all available users:

```
cat /etc/passwd
```

Change user

```
su ubuntu
```

Become root as normal user (sudo-way)

```
sudo -i
```

Check logged-on users

```
w
who
users
last
ps aux | grep bash
```

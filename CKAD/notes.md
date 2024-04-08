# CKAD Notes

## NOTES

Since I took CKA first, these notes will only contain stuff not already covered
by my CKA notes!

New playground service: https://labs.play-with-k8s.com/

## 4. Multi-Container Pods

Multi-Container pods

- share same lifecycle (created and destroyed together)
- share same networkspace (can refer to each other as localhost)
- have access to same storage volumes (no volume sharing service required!)
- available for 'regular' containers as well as initContainers (will run in
  sequential order!)

pod manifest -> reason why containers is an array: can define multiple images

Design Patterns

- Sidecar: e.g. logging agent forwarding logs to central server
- Adapter: e.g. process logs / convert to common format before sending to server
- Ambassador: e.g. proxy request to right DB (dev/test/prod) while refering to
  them as localhost

## 5. Observability

### 5.1 Readiness and Liveness Probes

pod status only gives high-level summary of pod and can only be one of

- ContainerCreateing
- Running
- Pending

additional information through pod conditions (each either TRUE or FALSE)

- PodScheduled
- Initialized
- ContainersReady
- Ready

BUT: ready only means all containers in pod are "RUNNING" and pod is ready to
accept user traffic. no information on applications and if THEY are ready, e.g.
Jenkins needs some time to startup and till then is not ready to accept requests.
-> no reflection of the status on application level!
-> READY may not always mean READY ;-)

Why important?

- services rely on pod's ready-condition and will blindly route user traffic to
  pods with possibly unready apps

Solution:

- readiness probes in form of
  - HTTP test, e.g. /api/ready
  - TCP test, e.g. for databases port 3306
  - execute cmd or custom script
- only of probe successful, pod will go in READY state

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: goproxy
      image: registry.k8s.io/goproxy:0.1
      ports:
        - containerPort: 8080
      # HTTP
      readinessProbe:
        httpGet:
          port: 8080
          path: /api/ready
      # TCP
      readinessProbe:
        tcpSocket:
          port: 8080
      # custom command
      readinessProbe:
        exec:
          command:
            - cat
            - /app/is_ready
      # HTTP with additional config
      readinessProbe:
        httpGet:
          port: 8080
          path: /api/ready
        initialDelaySeconds: 10
        periodSeconds: 5
        failureThreshold: 8
```

Complementary: Liveness probes

- what if app crashed but container stays READY?
- on fail, destroy and re-create CONTAINER (not POD)

Difference between liveness & readiness:

0. startup

- indicate if container application inside container has started
- if provided, all other probes are disabled
  once succeded, liveness prove takes over

1. readiness

- diagnostic check of container is alive
- indicate if container is ready to serve traffic (being ready)
- on fail: isolate pod, stop serving traffic

2. liveness

- ensure container is healthy to serve incoming traffic
- indicates if container has started and is alive (being available)
- doesn't wait for readiness probes to succeed -> use initialDelaySeconds
- on fail: pod unhealthy, restart container

Again:

- ReadinessProbes and LivenessProbes will be executed periodically all the time.
- If a StartupProbe is defined, ReadinessProbes and LivenessProbes won't be executed until the StartupProbe succeeds.
- ReadinessProbe fails\*: Pod won't be marked Ready and won't receive any traffic
- LivenessProbe fails\*: The container inside the Pod will be restarted
- StartupProbe fails\*: The container inside the Pod will be restarted

\*fails: fails more times than configured with failureThreshold

## 6 Pod Design

### Labels & Selectors

```
# long and short form
k get pods --selector|-l key=value
k get pods -l key=value

# cound pods with certain label
k get pods -l key=value --no-headers | wc -l
```

Label filtering in action

```
# add additional label to pods with label type=runner
k -n sun label pod -l type=runner protected=true # run for label runner

# for multiple label filters
k -n sun label pod -l "type in (worker,runner)" protected=true
```

### Rolling Updates & Rollbacks in Deployments

Rollouts and Versioning

- on creation of a deployment, it triggers a rollout which creates revision 1
- on each container update, a new rollout is triggered, revision is incremented

```
k rollout status deployment <name>
k rollout status deployment <name> --revision <int>
k rollout history deployment <name>
k rollout history deployment <name> --revision <int> # shows details like image
```

Depoyment strategies

- Recreate -> app down during update
- Rolling (default) -> successively replace pods

Rolling Update Strategy:

- maxUnavailable -> max. batch size of recreated pods at a time
- maxSurge -> max. number of pods to create on top of DESIRED
- both by default 25%

How to update?

```
k apply -f deploy.yaml
k set image mydeployment nginx-container=nginx:1.9.1
```

Setting change cause (`--record` option will be deprecated)

```
> kubectl rollout history deployment/nginx-deployment

deployments "nginx-deployment"
REVISION    CHANGE-CAUSE
1           kubectl apply --filename=https://k8s.io/examples/controllers/nginx-deployment.yaml
2           kubectl set image deployment/nginx-deployment nginx=nginx:1.16.1
3           kubectl set image deployment/nginx-deployment nginx=nginx:1.161
```

correct way to alter nowadays:

```
kubectl annotate deployment/nginx-deployment kubernetes.io/change-cause="image updated to 1.16.1"
```

Rollbacks

```
k rollout undo deployment <name>
k rollout undo deployment nginx --to-revision=1
```

Restart

```
k rollout restart deployment/mydeploy
```

### Blue/Green and Canary Strategy

NOTE: Cannot be specified as deployment strategy but implemented in a different way:

Blue/Green

- old version = blue, new version = green
- both deployed alongside each other
- traffic goes 100% to old version, green is tested simultaneously
- after all tests have passed, switch 100% to green
- best implemented with service meshes like istio
- manual implementation using 1 service pointing to either deployment with 2 different labels,
  e.g. version=v1, version=v2

Canary:

- create additional pod with new version
- route small amount of traffic to it
- looks good? -> run full rolling update
- manual implementation: two deployments with version=v1/v2 label and an
  additional common label app=front-end
- use label selector on "app" in service definition
- balance percentage via number of pods in both deployments
  (for percentage-based routing we need a service mesh)

### (Cron-)Jobs

Short-living workload for batch processing or regular tasks.

Manifest similar to pods

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: pi
spec:
  template:
    spec:
      containers:
        - name: pi
          image: perl:5.34.0
          command: ["perl", "-Mbignum=bpi", "-wle", "print bpi(2000)"]
      restartPolicy: Never
  backoffLimit: 4
```

Parallel execution

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: pi
spec:
  completions: 3 # can be ommited, defaults to value of parallelism!
  parallelism: 3
```

CronJob syntax

```
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of the month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday)
# │ │ │ │ │                                   OR sun, mon, tue, wed, thu, fri, sat
# │ │ │ │ │
# │ │ │ │ │
# * * * * *
```

Be careful! Now we have 3 different spec blocks: 1x cronjob, 1x job, 1x pod

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: hello
              image: busybox:1.28
              imagePullPolicy: IfNotPresent
              command:
                - /bin/sh
                - -c
                - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure
```

```
# Create a job
kubectl create job my-job --image=busybox

# Create a job with a command
kubectl create job my-job --image=busybox -- date

# Create a job from a cron job named "a-cronjob"
kubectl create job test-job --from=cronjob/a-cronjob
```

## 8. State Persistence

### 8.3 StatefulSets

Why deployments are not sufficient?
Example HA Database:

- replication from primary to secondaries
  -> pods need identity and creation order is important
- deployments have random names, statefulset pods have static names

- ordered, graceful deployment & scaling -> pods are created/destroyed one
  after the other (override: `podManagementPolicy: Parallel|OrderedReady`)
- stable, unique network identifier
- require headless services (see below)

### 8.4 Headless Services

For deployments:

- services loadbalance to all pods in a deployment
- services has own IP and DNS name, e.g. `myservice.default.svc.cluster.local`

For primary/secondary topologies:

- writes only allowed for primary
- data can be read from all, primary and secondary

-> point webserver to primary only!

Solution:

- could use IP address, but they are dynamic on creation -> no help
- pod's DNS has same problem because it is created from pod's IP address,
  e.g. `10-40-2-8.default.pod.cluster.local`

-> need service that does not loadbalance requests but gives DNS entry to reach
each pod

Headless Services
https://kubernetes.io/docs/concepts/services-networking/service/#headless-services

- created like normal services (ClusterIP, NodePort)
- does not have an IP of its own
- does not loadbalance
- only provides DNS for each pod using podname and namespace, e.g.
  `podname.headless-servicename.namespace.svc.cluster-domain.example` or
  `mysql-1.mysql-h.default.svc.cluster.local`

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mysql-h
spec:
  clusterIP: None # <- this defines a headless service
  selector:
    app: mysql
  ports:
    - port: 3306
```

For single pods or deployments you would need to set the hostname and subdomain
name for it to work, see https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-hostname-and-subdomain-fields, like so:

```yaml
apiVersion: v1
kind Pod
metadata:
  name: myapp-pod
  labels:
    app: mysql
  spec:
    containers:
    - name: mysql
      image: mysql
    subdomain: mysql-h  # <- need to be same as in headless service
    hostname: mysql-pod
```

!! For StatefulSets this is not required! The controller will take care of that!

But how does a statefulset know which headless service it belongs to?
-> need to specify the serviceName explicitly!

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: mysql
  serviceName: mysql-h
  replicas: 3
  template:
    metadata:
      labels:
        app: mysql
    spec:
      containers:
        - name: mysql
          image: mysql
```

### 8.5 Storage in StatefulSets

For pods either:

- Static Provisioning: PV (mode, size, backend) -> PVC (mode, request) -> Pod (claim name)
- Dynamic Provisioning: SC (backend) -> PVC (mode, request, SC name) -> Pod (claim name)

For Deployments/StatefulSets:

- all pods would try to use the same volume (possible with RWX, if that's what you want!)
- but for DBs, each pod need their own local storage, i.e. N different PVCs and therefore PVs

Auto-create PVC using templates:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  [...]
  template:
    metadata:
      labels:
        app: nginx # has to match .spec.selector.matchLabels
    spec:
      containers:
      - name: nginx
        image: registry.k8s.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi
```

Storage lifecycle

STS do not automatically delete PVC but instead ensures a pod is always
attached to the same PVC in case of, e.g. failure, restart, rescheduling on
other node etc.
-> stable storage for STS pods

## 9. Security

### API Versions

NOTE: `kubectl convert` subcommand has been deprecated/removed and is not
available as [plugin](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-convert-plugin).

## Helm

For complex services, avoid maintaining multiple small manifest files.

Instead create Helm Chart with required values as variables.
-> package manager for k8s

Concepts:

- convert manifest files into templates by replacing values with variables
  value -> `{{ .Values.variable_name }}`
- templates + values file = chart
- repos at `artifacthub.io`

```
# search on artifacthub
helm search hub wordpress

# add bitnami repo and search there
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo list
helm search repo wordpress      # search for string in all repos
helm search repo <reponame> -l  # shows all versions of all charts in a repo

# install charts
helm install [release-name] [chart-name]
helm install release-1 bitnami/wordpress
helm install release-2 bitnami/wordpress

# list installed charts
helm list -n <ns>
helm list -A

# uninstall charts/packages
helm uninstall

# only download but do not install
# -> useful when modifying templates, then install from local copy
helm pull --untar bitnami/wordpress
vim wordpress/templates/*
helm install release-4 ./wordpress

# other
helm upgrade
hel rollback
```

# Misc Notes

### Ingress

Ingress rules can be created via imperative `create` command! <br>
(still...better copy yaml block from docs. syntax is too error prone)

```
kubectl create ingress ingress --rule="ckad-mock-exam-solution.com/video*=my-video-service:8080" --dry-run=client -oyaml > ingress.yaml
```

### DNS

NOTE: does not work from nodes! need to exec into container! <br>
NOTE: for exec, `-it` seem not to be necessary here!

`sm5` -> silent and max. 5sec wait

**!WARNING!** better not use 1sec, b/c sometimes it just takes a sec and thus will yield
false results. if in doubt, check output by reming `-s` flag.

```
# if service available
k -n space1 exec app1-0 -- curl -sm5 microservice1.space2.svc.cluster.local

# to pods
k -n space1 exec app1-0 -- curl -sm5 192-168-0-9.space2.pod.cluster.local

# DNS check, also works for svc
k -n space1 exec app1-0 -- nslookup google.com
k -n space1 exec app1-0 -- nslookup service.namespace.svc.cluster.local
```

Check from temporary pod (all cmdline options are essential here!)

```
k run tmp --image=busybox:1.28 --rm -it --restart=Never -- curl -sm5 <dns>
```

### Fast find broken services

```
k get endpoints
```

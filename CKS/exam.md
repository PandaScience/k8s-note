## TODO

- ImagePolicyWebHook
- Falco vs. Sysdig: https://www.udemy.com/course/certified-kubernetes-security-specialist/learn/lecture/23184412#questions/18777106
- TLS config etcd/apiserver: https://www.udemy.com/course/certified-kubernetes-security-specialist/learn/lecture/23184412#questions/18776944
- https://jihadbenabra.medium.com/my-feedback-about-kubernetes-security-specialist-exam-a82b1af1a08c
- pod -> serviceaccount -> automount

## Experiences

### KillerSh

https://killer.sh/faq

### Questions

Source: https://www.reddit.com/r/kubernetes/comments/10zy8uj/just_passed_my_cks_exam/

NOPE:

- PSP's
- OPA/gatekeeper
- cluster upgrade
- kubernetes dashboard

FOR SURE:

- RBAC (be quick with this)
- Falco (you should be able to dream this)
- Networkpolicies
- ETCD/KUBE-API static pod config
- Dockerfile/YAML manual code review
- enabling/configuring audit logging
- enabling/configuring imagepolicywebhook
- trivy image scans
- fixing kube-bench issues
- extracting data from secrets (NOT from the ETCD with etcdctl directly)
- verifying platform binaries
- enabling apparmor profile/using it in a pod
- creating runtimeclass/using it in a pod
- immutability (securitycontext: readonlyfilesystem) in a pod.

### Medium

https://moabukar.medium.com/where-to-begin-with-the-cks-exam-5cf0dcc86f76

### MISC

KataContainers, Container vs SlimVMA:
https://www.udemy.com/course/certified-kubernetes-security-specialist/learn/lecture/23184412#questions/17695028

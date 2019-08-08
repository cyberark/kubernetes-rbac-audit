# ExtensiveRoleCheck

`ExtensiveRoleCheck` is a python tool that scanning the Kubernetes RBAC for risky roles in an offlline mode. The tool is a part of the "Kubernetes Pentest Methdology" blog post series.
```
usage: ExtensiveRoleCheck.py [-h] [--clusterRole CLUSTERROLE] [--role ROLE]  
                           [--rolebindings ROLEBINDINGS]  
                           [--cluseterolebindings CLUSETEROLEBINDINGS]
```


## Overview
The RBAC API is a set of roles that administrators can configure to limit access to the Kubernetes resources. The *ExtensiveRoleCheck* automate the searching process and output the risky roles and rolebindings found in the RBAC API. 

## Requirements:

*ExtensiveRoleCheck* work in offline mode, it means that you should first export the following `JSON` from your Kubernetes cluster configuration:

 - Roles 
 - ClusterRoles 
 - RoleBindings 
 - ClusterRoleBindings

To export those files you will need access permissions in the Kubernetes cluster. To export them, you might use the following commands:
** Export RBAC Roles:**
```
kubectl get roles --all-namespaces -o json
```
** Export RBAC ClusterRoles:**
```
kubectl get clusterroles -o json
```
** Export RBAC RolesBindings:**
```
kubectl get rolebindings --all-namespaces -o json
```
** Export RBAC Cluster RolesBindings:**
```
kubectl get clusterrolebindings -o json
```
## Output example:

import json
import argparse
import logging
from colorama import init, Fore, Back, Style

def get_argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--clusterRole', type=str, required=False, help='ClusterRoles JSON file',)
    parser.add_argument('--role', type=str, required=False, help='roles JSON file')
    parser.add_argument('--rolebindings', type=str, required=False, help='RoleBindings JSON file')
    parser.add_argument('--cluseterolebindings', type=str, required=False, help='ClusterRoleBindings JSON file')
    return parser.parse_args()

# Read data from files
def open_file(file_path):
    with open(file_path) as f:
        return json.load(f)

class ExtensiveRolesChecker(object):
    def __init__(self, json_file, role_kind):
        init()
        self._role = logging.getLogger(role_kind)
        self._role_handler = logging.StreamHandler()
        self._role_format = logging.Formatter(f'{Fore.YELLOW}[!][%(name)s]{Fore.WHITE}\u2192 %(message)s')
        self._role_handler.setFormatter(self._role_format)
        self._role.addHandler(self._role_handler)
        self._json_file = json_file
        self._results = {}
        self._generate()

    @property
    def results(self):
        return self._results

    def add_result(self, name, value):
        if not name:
            return
        if not (name in self._results.keys()):
            self._results[name] = [value]
        else:
            self._results[name].append(value)

    def _generate(self):
        for entity in self._json_file['items']:
            role_name = entity['metadata']['name']
            if entity['rules'] is None:
                continue
            for rule in entity['rules']:
                if not rule.get('resources', None):
                    continue
                self.get_read_secrets(rule, role_name)
                self.clusteradmin_role(rule, role_name)
                self.any_resources(rule, role_name)
                self.any_verb(rule, role_name)
                self.high_risk_roles(rule, role_name)
                self.role_and_roleBindings(rule, role_name)
                self.create_pods(rule, role_name)
                self.pods_exec(rule, role_name)
                self.pods_attach(rule, role_name)

    #Read cluster secrets:
    def get_read_secrets(self, rule, role_name):
        verbs = ['*','get','list']
        if ('secrets' in rule['resources'] and any([sign for sign in verbs if sign in rule['verbs']])):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to list secrets!')
                self.add_result(filtered_name, 'Has permission to list secrets!')

    #Any Any roles
    def clusteradmin_role(self, rule, role_name):
        if ('*' in rule['resources'] and '*' in rule['verbs']):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has Admin-Cluster permission!')
                self.add_result(filtered_name, 'Has Admin-Cluster permission!')

    #get ANY verbs:
    def any_verb(self, rule, role_name):
        resources = ['secrets',
                    'pods',
                    'deployments',
                    'daemonsets',
                    'statefulsets',
                    'replicationcontrollers',
                    'replicasets',
                    'cronjobs',
                    'jobs',
                    'roles',
                    'clusterroles',
                    'rolebindings',
                    'clusterrolebindings',
                    'users',
                    'groups']
        found_sign = [sign for sign in resources if sign in rule['resources']]
        if not found_sign:
            return
        if '*' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to access {found_sign[0]} with any verb!')
                self.add_result(filtered_name, f'Has permission to access {found_sign[0]} with any verb!')

    def any_resources(self, rule, role_name):
        verbs = ['delete','deletecollection', 'create','list' , 'get' , 'impersonate']
        found_sign = [sign for sign in verbs if sign in rule['verbs']]
        if not found_sign:
            return
        if ('*' in rule['resources']):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to use {found_sign[0]} on any resource!')
                self.add_result(filtered_name, f'Has permission to use {found_sign[0]} on any resource')

    def high_risk_roles(self, rule, role_name):
        verb_actions = ['create','update']
        resources_attributes = ['deployments','daemonsets','statefulsets','replicationcontrollers','replicasets','jobs','cronjobs']
        found_attribute = [attribute for attribute in resources_attributes if attribute in rule['resources']]
        if not (found_attribute):
            return
        found_actions = [action for action in verb_actions if action in rule['verbs']]
        if not (found_actions):
            return
        filtered_name = self.get_non_default_name(role_name)
        if filtered_name:
            self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to {found_actions[0]} {found_attribute[0]}!')
            self.add_result(filtered_name, f'Has permission to {found_actions[0]} {found_attribute[0]}!')

    def role_and_roleBindings(self, rule, role_name):
        resources_attributes = ['rolebindings','roles','clusterrolebindings']
        found_attribute = [attribute for attribute in resources_attributes if attribute in rule['resources']]
        if not found_attribute:
            return
        if ('create' in rule['verbs']):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to create {found_attribute[0]}!')
                self.add_result(filtered_name, f'Has permission to create {found_attribute[0]}!')


    def create_pods(self, rule, role_name):
        if 'pods' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to create pods!')
                self.add_result(filtered_name, 'Has permission to create pods!')

    def pods_exec(self, rule, role_name):
        if 'pods/exec' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to use pod exec!')
                self.add_result(filtered_name, 'Has permission to use pod exec!')

    def pods_attach(self, rule, role_name):
        if 'pods/attach' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to attach pods!')
                self.add_result(filtered_name, 'Has permission to attach pods!')

    @staticmethod
    def get_non_default_name(name):
        if not ((name[:7] == 'system:') or (name == 'edit') or (name == 'admin') or (name == 'cluster-admin') or (name == 'aws-node') or (name[:11] == 'kubernetes-')):
            return name


class roleBingingChecker(object):
    def __init__(self, json_file, extensive_roles, bind_kind):
        self._json_file = json_file
        self._extensive_roles = extensive_roles
        self._bind_kind = bind_kind
        self._results = []
        self.bindsCheck()

    def bindsCheck(self):
        _rolebiding_found = []
        for entity in self._json_file['items']:
            _role_name = entity['metadata']['name']
            _rol_ref = entity['roleRef']['name']
            if not entity.get('subjects', None):
                continue
            if _rol_ref in self._extensive_roles:
                _rolebiding_found.append(_rol_ref)
                for sub in entity['subjects']:
                    if not sub.get('name', None):
                        continue
                    self.print_rolebinding_results(sub, _role_name, self._bind_kind)
        return _rolebiding_found

    def print_rolebinding_results(self, sub, role_name, bind_kind):
        if sub['kind'] == 'ServiceAccount':
            print(f'{Fore.YELLOW}[!][{bind_kind}]{Fore.WHITE}\u2192 ' + f'{Fore.GREEN}{role_name}{Fore.RED} is binded to {sub["name"]} ServiceAccount.')
        else:
            print(f'{Fore.YELLOW}[!][{bind_kind}]{Fore.WHITE}\u2192 ' + f'{Fore.GREEN}{role_name}{Fore.RED} is binded to the {sub["kind"]}: {sub["name"]}!')



if __name__ == '__main__':
    args = get_argument_parser()
    if args.clusterRole:
        print('\n[*] Started enumerating risky ClusterRoles:')
        role_kind = 'ClusterRole'
        clusterRole_json_file = open_file(args.clusterRole)
        extensiveClusterRolesChecker = ExtensiveRolesChecker(clusterRole_json_file, role_kind)
        extensive_ClusterRoles = [result for result in extensiveClusterRolesChecker.results]

    if args.role:
        print(f'{Fore.WHITE}[*] Started enumerating risky Roles:')
        role_kind = 'Role'
        Role_json_file = open_file(args.role)
        extensiveRolesChecker = ExtensiveRolesChecker(Role_json_file, role_kind)
        extensive_roles = [result for result in extensiveRolesChecker.results if result not in extensive_ClusterRoles]
        extensive_roles = extensive_roles + extensive_ClusterRoles

    if args.cluseterolebindings:
        print(f'{Fore.WHITE}[*] Started enumerating risky ClusterRoleBinding:')
        bind_kind = 'ClusterRoleBinding'
        clusterRoleBinding_json_file = open_file(args.cluseterolebindings)
        extensive_clusteRoleBindings = roleBingingChecker(clusterRoleBinding_json_file, extensive_roles, bind_kind)

    if args.rolebindings:
        print(f'{Fore.WHITE}[*] Started enumerating risky RoleRoleBindings:')
        bind_kind = 'RoleBinding'
        RoleBinding_json_file = open_file(args.rolebindings)
        extensive_RoleBindings = roleBingingChecker(RoleBinding_json_file, extensive_roles, bind_kind)

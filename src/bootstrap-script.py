import os
import sys
import json
import requests
import logging
from dotenv import load_dotenv
from typing import Any, Dict, List, Optional, Callable

load_dotenv()
logging.basicConfig(level=logging.INFO)


class KeycloakError(Exception):
    """Custom exception for Keycloak-related errors."""
    pass


def handle_keycloak_errors(func: Callable) -> Callable:
    """Decorator to handle exceptions from Keycloak API calls."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.HTTPError as e:
            response = e.response
            logging.error(f"HTTP Error {response.status_code} during {func.__name__}: {response.text}")
            raise KeycloakError(f"Keycloak API error: {response.status_code} {response.reason}")
        except requests.RequestException as e:
            logging.error(f"Request error during {func.__name__}: {e}")
            raise KeycloakError("Network error when communicating with Keycloak.")
        except Exception as e:
            logging.error(f"Unexpected error during {func.__name__}: {e}")
            raise
    return wrapper


class Config:
    """Configuration loader for the Keycloak setup."""

    def __init__(self) -> None:
        self.load_config()

    def load_config(self) -> None:
        """Loads configuration from environment variables."""
        try:
            self.WELL_KNOWN_URLS: Dict[str, str] = json.loads(os.environ.get('WELL_KNOWN_URLS', '{}'))
            self.ZDL_CONFIG: Dict[str, Any] = json.loads(os.environ.get('ZDL_CONFIG', '{}'))
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in environment variables: {e}")
            raise

        # Keycloak Connection Config
        self.KEYCLOAK_BASE_URL: str = self.WELL_KNOWN_URLS.get('zekoder-keycloak-service-base-url', '')
        self.REALM_NAME: str = self.ZDL_CONFIG.get('solution', {}).get('name', '')

        # Validate required configurations
        if not self.KEYCLOAK_BASE_URL:
            logging.error("KEYCLOAK_BASE_URL is not set in WELL_KNOWN_URLS.")
            raise ValueError("KEYCLOAK_BASE_URL is not set.")
        if not self.REALM_NAME:
            logging.error("REALM_NAME is not set in ZDL_CONFIG.")
            raise ValueError("REALM_NAME is not set.")

        # Load ZDL Config
        self.SECURITY_CONFIG: Dict[str, Any] = self._get_security_config()
        self.TEMPLATES_CONFIG: List[Dict[str, Any]] = self._get_templates_config()
        self.ATTRIBUTES_CONFIG: Dict[str, Any] = self._get_attributes_config()

        # Keycloak runtime config
        self.KC_MASTER_USER_NAME: str = self.SECURITY_CONFIG.get('master_user', {}).get('username', 'admin')
        self.KC_MASTER_PASSWORD: str = os.environ.get('KEYCLOAK_ADMIN_PASSWORD', 'admin')
        self.KC_MASTER_USER_GROUPS: List[str] = self.SECURITY_CONFIG.get('master_user', {}).get('groups', [])

        self.KEYCLOAK_ADMIN: str = os.environ.get('KEYCLOAK_ADMIN', 'admin')
        self.KEYCLOAK_ADMIN_PASSWORD: str = os.environ.get('KEYCLOAK_ADMIN_PASSWORD', 'admin')

    def _get_security_config(self) -> Dict[str, Any]:
        """Returns the security configuration from the ZDL_CONFIG."""
        security_config = self.ZDL_CONFIG.get('security', {})
        if not security_config:
            logging.warning("Security configuration is missing in ZDL_CONFIG.")
        return security_config

    def _get_templates_config(self) -> List[Dict[str, Any]]:
        """Returns the templates configuration from the ZDL_CONFIG."""
        templates_config = self.ZDL_CONFIG.get('templates', [])
        if not templates_config:
            logging.warning("Templates configuration is missing in ZDL_CONFIG.")
        return templates_config

    def _get_attributes_config(self) -> Dict[str, Any]:
        """Returns the attributes configuration from the ZDL_CONFIG."""
        attributes_config = self.SECURITY_CONFIG.get('settings', {}).get('attributes', {})
        if not attributes_config:
            logging.warning("Attributes configuration is missing in SECURITY_CONFIG.")
        return attributes_config


class KeycloakRealm:
    """Class to build Keycloak Realm configuration based on provided settings."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.realm_name: str = config.REALM_NAME
        self.realm_config: Dict[str, Any] = {}

    def build_realm_json(self) -> Dict[str, Any]:
        """Builds and returns the realm JSON configuration for Keycloak."""
        self.realm_config = self.get_std_realm_json('keycloak-realm.json')

        # Update Security Config
        groups_roles = self.config.SECURITY_CONFIG.get('groups_roles', {})
        self._update_roles_and_groups(groups_roles)

        # Update SMTP provider
        smtp_config = self.config.SECURITY_CONFIG.get('email_provider', {}).get('creds', {})
        self._update_smtp_server(smtp_config)

        # Add master user
        self._add_master_user(
            self.config.KC_MASTER_USER_NAME,
            self.config.KC_MASTER_PASSWORD,
            self.config.KC_MASTER_USER_GROUPS
        )

        # Update email templates and signin/signup pages (attributes)
        self._update_attributes(self.config.ATTRIBUTES_CONFIG, self.config.TEMPLATES_CONFIG)

        return self.realm_config

    def get_std_realm_json(self, realm_json_path: str = 'keycloak-realm.json') -> Dict[str, Any]:
        """Reads and returns a standard realm JSON, replacing placeholders with actual values."""
        realm_json_path = os.path.join(os.path.dirname(__file__), realm_json_path)
        try:
            with open(realm_json_path, 'r') as f:
                raw_json = f.read()
        except FileNotFoundError:
            logging.error(f"Keycloak realm JSON file not found: {realm_json_path}")
            raise
        except Exception as e:
            logging.error(f"Error reading realm JSON file: {e}")
            raise

        raw_json = raw_json.replace("realmnameplaceholder", self.realm_name)
        raw_json = raw_json.replace("clientsecretplaceholder", self.config.KEYCLOAK_ADMIN_PASSWORD)
        try:
            realm_json = json.loads(raw_json)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in realm JSON file: {e}")
            raise
        return realm_json

    def _update_roles_and_groups(self, groups_roles: Dict[str, Any]) -> None:
        """Updates roles and groups in the realm configuration."""
        added_roles: set = set()
        converted_data: Dict[str, Any] = {"groups": [], "roles": {"realm": []}}

        for group_name, group_info in groups_roles.items():
            converted_data["groups"].append({
                "name": group_name,
                "path": f"/{group_name}",
                "realmRoles": group_info["roles"]
            })

            for role in group_info["roles"]:
                if role not in added_roles:
                    converted_data["roles"]["realm"].append({
                        "name": role,
                        "containerId": "7d02fa90-0e12-4d27-bf9e-5a74e60be712"
                    })
                    added_roles.add(role)

        existing_realm_roles = self.realm_config.get("roles", {}).get("realm", [])
        converted_data["roles"]["realm"].extend(existing_realm_roles)
        converted_data["roles"]["client"] = self.realm_config.get("roles", {}).get("client", [])

        self.realm_config.update(converted_data)

    def _update_smtp_server(self, smtp_config: Dict[str, Any]) -> None:
        """Updates the SMTP server configuration in the realm configuration."""
        kc_smtp_config = {
            "replyToDisplayName": smtp_config.get('reply_to_display_name', ''),
            "starttls": smtp_config.get('secure', True),
            "auth": "true",
            "envelopeFrom": "",
            "ssl": "false",
            "password": smtp_config.get('password', ''),
            "port": smtp_config.get('port', '587'),
            "replyTo": smtp_config.get('reply_to', ''),
            "host": smtp_config.get('host', ''),
            "from": smtp_config.get('send_from', ''),
            "fromDisplayName": smtp_config.get('from_display_name', ''),
            "user": smtp_config.get('username', '')
        }
        self.realm_config['smtpServer'] = kc_smtp_config

    def _add_master_user(self, user_name: str, password: str, groups: List[str]) -> None:
        """Adds the master user to the realm configuration."""
        # users_list = self.realm_config.get("users", [])
        # master_user_config = {
        #     "username": user_name,
        #     "enabled": True,
        #     "credentials": [{"type": "password", "value": password, "temporary": False}],
        #     "groups": groups
        # }
        # users_list.append(master_user_config)
        # self.realm_config["users"] = users_list
        
        users_list = self.realm_config.get("users", [{}])
        master_user_config = users_list[-1]
        master_user_config["username"] = user_name
        master_user_config["credentials"][0]["value"] = password
        master_user_config["groups"] = groups
        self.realm_config["users"] = users_list

    def _update_attributes(self, attributes: Dict[str, Any], templates: List[Dict[str, Any]]) -> None:
        """Updates attributes in the realm configuration."""
        theme_attributes = self._get_theme_attributes(attributes)
        template_attributes = self._get_template_attributes(templates)

        if 'attributes' not in self.realm_config:
            self.realm_config['attributes'] = {}

        self.realm_config["attributes"].update(theme_attributes)
        self.realm_config["attributes"].update(template_attributes)

    def _get_theme_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Formats theme attributes keys to match Keycloak expected format."""
        return {
            f"_{key.replace('_', '.')}": value
            for key, value in attributes.items()
        }

    def _get_template_attributes(self, templates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepares template attributes for realm configuration."""
        template_attributes = {
            "_providerConfig.theme.email.parent": "mustache"
        }
        for template in templates:
            template_name = template.get('template_name', '')
            template_body = template.get('body', '')
            key = f"_providerConfig.theme.email.templates.html/{template_name}.mustache"
            template_attributes[key] = template_body
        return template_attributes


class KeycloakClient:
    """Client for interacting with Keycloak API."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self.base_url = base_url
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.token = self._get_admin_token()

    @handle_keycloak_errors
    def _get_admin_token(self) -> str:
        """Retrieves an admin access token from Keycloak."""
        url = f'{self.base_url}/realms/master/protocol/openid-connect/token'
        payload = {
            'client_id': 'admin-cli',
            'username': self.admin_username,
            'password': self.admin_password,
            'grant_type': 'password'
        }
        response = requests.post(url, data=payload)
        response.raise_for_status()
        return response.json()['access_token']

    @handle_keycloak_errors
    def request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Makes an authenticated request to the Keycloak API."""
        headers: dict = kwargs.pop('headers', {})
        headers.setdefault('Authorization', f'Bearer {self.token}')
        headers.setdefault('Content-Type', 'application/json')
        url = f'{self.base_url}{endpoint}'
        logging.debug(f"Making {method} request to {url}")
        logging.debug(f"Request headers: {headers}")
        logging.debug(f"Request data: {kwargs.get('json', '')}")
        response = requests.request(method, url, headers=headers, **kwargs)
        response.raise_for_status()
        return response

    @handle_keycloak_errors
    def get_user_token(self, realm_name: str, username: str, password: str) -> str:
        """Retrieves an access token for the specified user in the specified realm."""
        url = f'{self.base_url}/realms/{realm_name}/protocol/openid-connect/token'
        payload = {
            'client_id': 'solution-web',
            'username': username,
            'password': password,
            'grant_type': 'password',
            'scope': 'openid'
        }
        response = requests.post(url, data=payload)
        response.raise_for_status()
        return response.json()['access_token']


class KeycloakBootstrap:
    """Handles interactions with Keycloak to bootstrap and configure the realm."""

    def __init__(self, config: Config, realm_json: Dict[str, Any]) -> None:
        self.config = config
        self.realm = realm_json
        self.client = KeycloakClient(
            base_url=config.KEYCLOAK_BASE_URL,
            admin_username=config.KEYCLOAK_ADMIN,
            admin_password=config.KEYCLOAK_ADMIN_PASSWORD
        )
        self.realm_name: str = config.REALM_NAME

    @handle_keycloak_errors
    def bootstrap(self) -> None:
        """Bootstraps the Keycloak realm by creating or updating the realm configuration."""
        if self.check_realm_exists(self.realm_name):
            logging.info("Realm exists. Updating configuration...")
            self.update_groups_roles(self.realm.get('groups', []), self.realm.get('roles', {}))
            self.update_realm_config(self.realm)
        else:
            logging.info("Realm does not exist. Creating realm...")
            self.create_realm(self.realm)
            self.assign_user_to_org()

    @handle_keycloak_errors
    def check_realm_exists(self, realm_name: str) -> bool:
        """Checks if the specified realm exists in Keycloak."""
        try:
            self.client.request('GET', f'/admin/realms/{realm_name}')
            return True
        except KeycloakError as e:
            if "404" in str(e):
                return False
            else:
                raise

    @handle_keycloak_errors
    def create_realm(self, realm: Dict[str, Any]) -> None:
        """Creates a new realm in Keycloak."""
        self.client.request('POST', '/admin/realms', json=realm)
        logging.info(f"Realm '{self.realm_name}' created successfully.")

    @handle_keycloak_errors
    def update_groups_roles(self, groups: List[Dict[str, Any]], roles: Dict[str, Any]) -> None:
        """Updates the groups and roles in the realm using partial import API."""
        data = {
            'ifResourceExists': 'SKIP',
            'groups': groups,
            'roles': roles
        }
        self.client.request('POST', f'/admin/realms/{self.realm_name}/partialImport', json=data)
        logging.info("Groups and roles updated successfully.")

    @handle_keycloak_errors
    def update_realm_config(self, realm_config: Dict[str, Any]) -> None:
        """Updates the realm configuration using the given realm JSON."""
        self.client.request('PUT', f'/admin/realms/{self.realm_name}', json=realm_config)
        logging.info("Realm configuration updated successfully.")

    @handle_keycloak_errors
    def get_user(self, user_name: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user from Keycloak."""
        response = self.client.request(
            'GET',
            f'/admin/realms/{self.realm_name}/users',
            params={'username': user_name, 'exact': 'true'}
        )
        users = response.json()
        return users[0] if users else None

    @handle_keycloak_errors
    def add_master_user(self, user_name: str, password: str, groups: List[str]) -> None:
        """Adds the master user to the realm if not already present."""
        user = self.get_user(user_name)
        if user:
            logging.info(f"User '{user_name}' already exists.")
            return

        data = {
            'username': user_name,
            'enabled': True,
            'credentials': [{'type': 'password', 'value': password, 'temporary': False}],
            'groups': groups
        }
        self.client.request('POST', f'/admin/realms/{self.realm_name}/users', json=data)
        logging.info(f"User '{user_name}' created successfully.")

    @handle_keycloak_errors
    def create_org(self) -> None:
        """Creates an organization in Keycloak."""
        master_user = self.realm.get('users', [{}])[-1]
        user_token = self.client.get_user_token(
            self.realm_name,
            master_user['username'],
            master_user['credentials'][0]['value']
        )

        headers = {
            'Authorization': f'Bearer {user_token}',
            'Content-Type': 'application/json'
        }
        data = {'name': self.realm_name}
        url = f'/realms/{self.realm_name}/orgs'
        response = requests.post(f'{self.config.KEYCLOAK_BASE_URL}{url}', headers=headers, json=data)
        response.raise_for_status()
        logging.info(f"Organization '{self.realm_name}' created successfully.")

    @handle_keycloak_errors
    def assign_user_to_org(self) -> None:
        """Assigns the master user to the organization."""
        self.create_org()


def write_realm_json(realm_json: Dict[str, Any]) -> None:
    """Writes the realm JSON configuration to a file."""
    try:
        with open('keycloak-realm-new3.json', 'w') as f:
            json.dump(realm_json, f, indent=4)
        logging.info("Realm JSON configuration written to 'keycloak-realm-new.json'.")
    except Exception as e:
        logging.error(f"Error writing realm JSON to file: {e}")
        raise

def main() -> None:
    try:
        config = Config()
        realm_builder = KeycloakRealm(config)
        realm_json = realm_builder.build_realm_json()
        write_realm_json(realm_json)
        keycloak_bootstrap = KeycloakBootstrap(config, realm_json)
        keycloak_bootstrap.bootstrap()
    except Exception as e:
        logging.error(f"An error occurred during the bootstrap process: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

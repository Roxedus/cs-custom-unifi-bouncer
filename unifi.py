#!/usr/bin/env python3
import requests
import sys
import os
from ipaddress import ip_network, IPv4Network, IPv6Network
import logging
import logging.handlers


class UnifiAuthenticationException(Exception):
    pass


class Unifi:
    """Unifi API wrapper"""

    def __init__(self, username, password, base_url, authenticate=True):
        """
        Initialize the Unifi API
        :param ignore_ssl: Ignore Unifi SSL certificate validity
        :param username: Unifi username
        :param password: Unifi password
        :param base_url: Unifi API base URL
        :param site: Site (defaults to the default site)
        :param authenticate: Authenticate after instantiating class
        """
        # Set class-level variables
        self.ignore_ssl = os.environ.get("UNIFI_IGNORE_SSL", default="false")
        self.username = username
        self.password = password
        self.base_url = base_url
        self.site = os.environ.get("UNIFI_SITE")
        self.session = requests.Session()

        if self.ignore_ssl.lower() == "true":
            log.debug("Ignoring SSL")
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Authenticate
        if authenticate:
            self.authenticate()
    # Authenticate against the Unifi API

    def authenticate(self):
        """
        Authenticate against the Unifi API
        :return: authentication successful
        """
        self.session.headers.update({'referrer': f"{self.base_url}/login"})
        # Send credentials to API, check if successful
        if self.session.post(f"{self.base_url}/api/login",
                             json={'username': self.username, 'password': self.password}).json().get('meta').get(
                'rc') == 'ok':
            return True
        else:
            log.warning("Could not Authenticate")
            raise UnifiAuthenticationException

    def getFirewallGroup(self, group_id):
        """
        Get existing firewall group
        :return: firewall group info
        """
        firewallGroup = ''
        response = self.session.get(
            f"{self.base_url}/api/s/{self.site}/rest/firewallgroup/{group_id}", verify=False).json()
        if response.get('meta').get('rc') == 'ok' and len(response.get('data')) == 1:
            firewallGroup = response.get('data')[0]
        return firewallGroup if firewallGroup else False

    def editFirewallGroup(self, group_id, data):
        """
        Edit firewall group
        :return: edit successful
        """
        response = self.session.put(
            f"{self.base_url}/api/s/{self.site}/rest/firewallgroup/{group_id}", json=data, verify=False)
        if response.status_code == 200:
            return True
        return False


def main(argv):
    username = os.environ.get("UNIFI_USERNAME")
    password = os.environ.get("UNIFI_PASSWORD")
    base_url = os.environ.get("UNIFI_BASE_URL")
    group4_id = os.environ.get("UNIFI_IPV4_GROUP_ID")
    group6_id = os.environ.get("UNIFI_IPV6_GROUP_ID")

    unifi = Unifi(username, password, base_url)

    log.info(f"Connection made")
    log.debug(f"Args: {argv}")
    command = argv[1]
    ipaddr = argv[2]

    try:
        fam = ip_network(ipaddr)
        if type(fam) is IPv4Network:
            group_id = group4_id
            log.debug("Family is IPV4")
        elif type(fam) is IPv6Network:
            group_id = group6_id
            log.debug("Family is IPV6")
        else:
            log.error("Family is not found")
            sys.exit(f"Error: {ipaddr} is not a ip family")
    except ValueError:
        log.error(f"{ipaddr} is not a valid ip address")
        sys.exit(f"Error: {ipaddr} is not a valid ip address")
    current_rule = unifi.getFirewallGroup(group_id)
    log.debug(f"Current rule: {current_rule}")
    new_rule = ""

    if current_rule == False:
        log.error(msg)(f"No Rule found for group {group_id}")
        sys.exit("Error: Something went wrong getting the existing group")

    if command == 'add':
        log.info(f"Banning {ipaddr}")
        current_rule["group_members"].append(ipaddr)
        new_rule = unifi.editFirewallGroup(group_id, current_rule)
        l  # og.debug(f"New rule: {new_rule}")
    elif command == 'del':
        log.info(f"Un-Banning {ipaddr}")
        if ipaddr not in current_rule["group_members"]:
            log.error(f"{ipaddr} is not banned")
            sys.exit(f"Error: {ipaddr} is not banned")
        current_rule["group_members"].remove(ipaddr)
        new_rule = unifi.editFirewallGroup(group_id, current_rule)
        #log.debug(f"New rule: {new_rule}")
    else:
        log.error("Unknown command")
        sys.exit("Unknown command")

    if new_rule == False:
        log.error("New rule not set")
        sys.exit("Error: Something went wrong when updating the group")


# Main
if __name__ == "__main__":
    log = logging.getLogger("CS-Bouncer-Logger")

    file_handler = logging.handlers.WatchedFileHandler(
        os.environ.get("LOGFILE", "/var/log/cs.log"))
    formatter = logging.Formatter(logging.BASIC_FORMAT)
    file_handler.setFormatter(formatter)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)

    log.setLevel("DEBUG")
    log.addHandler(file_handler)
    log.addHandler(stdout_handler)

    log.info("Starting thing")

    main(sys.argv)

#!/usr/bin/env python3
import logging
import logging.handlers
import os
import sys
import time
from ipaddress import IPv4Network, IPv6Network, ip_network

import requests
from pycrowdsec.client import StreamClient as CrowdSecClient


class UnifiAuthenticationException(Exception):
    pass


class UnifiAPIException(Exception):
    pass


class Unifi:
    """Unifi API wrapper"""

    def __init__(self, username, password, base_url, site, authenticate=True):
        """
        Initialize the Unifi API
        :param ignore_ssl: Ignore Unifi SSL certificate validity
        :param username: Unifi username
        :param password: Unifi password
        :param base_url: Unifi API base URL
        :param site: Site
        :param authenticate: Authenticate after instantiating class
        """
        # Set class-level variables
        self.ignore_ssl = os.environ.get("UNIFI_IGNORE_SSL", default="false")
        self.username = username
        self.password = password
        self.base_url = base_url
        self.site = site
        self.session = requests.Session()

        if self.ignore_ssl.lower() == "true":
            log.debug("Ignoring SSL")
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Authenticate
        if authenticate:
            self.authenticate()

        log.info("Connection made to unifi")
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
        firewallGroup = []
        response = self.session.get(
            f"{self.base_url}/api/s/{self.site}/rest/firewallgroup/{group_id}", verify=False).json()
        if response.get('meta').get('rc') == 'ok' and len(response.get('data')) == 1:
            firewallGroup = response.get('data')[0]
        if response.get('meta').get('rc') == 'error':
            raise UnifiAPIException(response.get('meta').get('msg'))
        return firewallGroup

    def editFirewallGroup(self, group_id, data):
        """
        Edit firewall group
        :return: edit successful
        """
        payload = self.getFirewallGroup(group_id)
        payload["group_members"] = data
        response = self.session.put(
            f"{self.base_url}/api/s/{self.site}/rest/firewallgroup/{group_id}", json=payload, verify=False)
        assert response.json().get('meta').get('rc') == 'ok', response.get('meta').get('msg')
        return True


def main():
    username = os.environ.get("UNIFI_USERNAME")
    password = os.environ.get("UNIFI_PASSWORD")
    site = os.environ.get("UNIFI_SITE", default="Default")
    base_url = os.environ.get("UNIFI_BASE_URL", default="https://unifi-controller:8443")
    group4_id = os.environ.get("UNIFI_IPV4_GROUP_ID", default=False)
    group6_id = os.environ.get("UNIFI_IPV6_GROUP_ID", default=False)

    crowd = CrowdSecClient(
        api_key="b33dc8e982891b211b8cb0598f82d318",
        lapi_url="http://crowdsec:8080/"
    )

    crowd.run()

    log.info("Connection made to crowdsec")

    unifi = Unifi(username, password, base_url, site)

    if group4_id:
        fw_group = unifi.getFirewallGroup(group4_id)
        log.debug("There is currently %s items in the list %s", len(
            fw_group.get("group_members")), fw_group.get("name"))

    if group6_id:
        fw_group = unifi.getFirewallGroup(group6_id)
        log.debug("There is currently %s items in the list %s", len(
            fw_group.get("group_members")), fw_group.get("name"))

    while crowd.is_running():
        try:
            decisions = crowd.get_current_decisions()
            break
        except RuntimeError:
            pass

    time.sleep(3)

    ipv_4_decisions = []
    ipv_6_decisions = []

    bans = 0

    for i, action in decisions.items():
        if action != "ban":
            print(f"{i} is {action}")
        else:
            fam = ip_network(i)
            if isinstance(fam, IPv4Network):
                i = i.replace("/32", "")
                ipv_4_decisions.append(i)
                bans += 1
            elif isinstance(fam, IPv6Network):
                i = i.replace("/128", "")
                ipv_6_decisions.append(i)
                bans += 1
            else:
                log.warning("Halp dunno what to do with %s", i)

    log.debug("There is a total of %s decisions in CrowdSec. IPV4: %s IPV6: %s",
              len(decisions), len(ipv_4_decisions), len(ipv_6_decisions))

    if group4_id:
        unifi.editFirewallGroup(group4_id, ipv_4_decisions)
        log.debug("Adding IPv4 decisions to UniFi")

    if group6_id:
        unifi.editFirewallGroup(group4_id, ipv_6_decisions)
        log.debug("Adding IPv6 decisions to UniFi")


# Main
if __name__ == "__main__":
    log = logging.getLogger("CS-Bouncer-Logger")

    file_handler = logging.handlers.WatchedFileHandler(
        os.environ.get("LOGFILE", "cs.log"))  # /var/log/
    formatter = logging.Formatter(logging.BASIC_FORMAT)
    file_handler.setFormatter(formatter)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)

    log.setLevel("DEBUG")
    log.addHandler(file_handler)
    log.addHandler(stdout_handler)

    log.info("Starting thing")

    main()

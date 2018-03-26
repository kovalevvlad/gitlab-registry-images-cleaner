#!/usr/bin/env python

import logging
import json
import requests


class GitlabRegistryClient(object):
    """Client for Gitlab registry"""

    def __init__(self, auth, jwt, registry, requests_verify=True, dry_run=False):
        """ Initializing arguments """
        self.auth = auth
        self.jwt = jwt.rstrip('//')
        self.registry = registry.rstrip('//')
        self.requests_verify = requests_verify
        self.dry_run = dry_run
        self.tokens = dict()  # Cache for bearer tokens

    def get_bearer(self, scope):
        """Return bearer token from Gitlab jwt"""
        if scope not in self.tokens:
            url = "{}/?service=container_registry&scope={}:*".format(self.jwt, scope)
            response = requests.get(url, auth=self.auth, verify=self.requests_verify)
            response.raise_for_status()
            token = response.json()
            self.tokens[scope] = token["token"]
        return self.tokens[scope]

    def get_json(self, path, scope):
        """Return JSON from registry"""
        headers = {"Authorization": "Bearer " + self.get_bearer(scope)}
        response = requests.get(self.registry + path, headers=headers, verify=self.requests_verify)
        if response.status_code == 200 or response.status_code == 404:
            json_r = response.json()
            if "errors" in json_r:
                if json_r["errors"][0]["message"] != "manifest unknown":
                    logging.error(json_r["errors"][0]["message"])
            return json_r
        else:
            response.raise_for_status()

    def get_tags(self, repo):
        """Return tags of repository from registry"""
        return self.get_json("/v2/{}/tags/list".format(repo),
                             "repository:" + repo)

    def get_manifest(self, repo, tag):
        """Return manifest of tag from registry"""
        return self.get_json("/v2/{}/manifests/{}".format(repo, tag),
                             "repository:" + repo)

    def get_image(self, repo, tag):
        """Return image by manifest from registry"""
        manifest = self.get_manifest(repo, tag)
        if "errors" in manifest:
            if tag != 'latest':
                logging.info("Image {}:{} not found or already deleted: {}".format(
                    repo, tag, manifest["errors"][0]["message"]))
            return {}
        else:
            return json.loads(manifest["history"][0]["v1Compatibility"])

    def get_digest(self, repo, tag):
        """Return digest for manifest from registry"""
        path = "/v2/{}/manifests/{}".format(repo, tag)
        headers = {
            "Authorization": "Bearer " + self.get_bearer("repository:" + repo),
            "Accept": "application/vnd.docker.distribution.manifest.v2+json"
        }
        response = requests.head(self.registry + path, headers=headers, verify=self.requests_verify)
        return response.headers["Docker-Content-Digest"]

    def delete_image(self, repo, tag):
        """Delete image by tag from registry"""
        url = "/v2/{}/manifests/{}".format(repo, self.get_digest(repo, tag))
        logging.debug("Delete URL: {}{}".format(self.registry, url))
        if self.dry_run:
            logging.warning("~ Dry Run!")
        else:
            headers = {
                "Authorization": "Bearer " + self.get_bearer("repository:" + repo)
            }
            response = requests.delete(self.registry + url, headers=headers, verify=self.requests_verify)
            # We allow 404 in case there is a race between 2 deletes
            if response.status_code in (202, 404):
                logging.info("+ OK")
            else:
                logging.error(response.text)


if __name__ == "__main__":
    import argparse
    import datetime
    import os

    config_name = os.path.basename(__file__).replace(".py", ".ini")
    parser = argparse.ArgumentParser(
        description="Utility to remove Docker images from the Gitlab registry",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--jwt-url", required=True)
    parser.add_argument("--registry-url", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "-t",
        "--tag-match",
        help="only consider tags containing the string",
        metavar="SNAPSHOT")
    parser.add_argument(
        "--hours",
        help="delete images older than this many hours",
        metavar="X",
        required=True,
        type=int)
    parser.add_argument(
        "--clean-all",
        action="store_true",
        help="delete all images in repository (DANGER!)")
    parser.add_argument(
        "--user",
        required=True,
        help="gitlab registry user")
    parser.add_argument(
        "--password",
        required=True,
        help="gitlab registry password")
    parser.add_argument(
        "--dry-run", action="store_true", help="not delete actually")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="verbose mode")
    parser.add_argument(
        "-z", "--insecure", action="store_true", help="disable SSL certificate verification")
    parser.add_argument("--debug", action="store_true", help="debug output")
    args = parser.parse_args()

    log_format = "[%(asctime)s] %(levelname)-8s %(message)s"
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format=log_format)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO, format=log_format)
        logging.getLogger("requests").setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.WARNING, format=log_format)

    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    GRICleaner = GitlabRegistryClient(
        auth=(args.user, args.password),
        jwt=args.jwt_url,
        registry=args.registry_url,
        requests_verify=not args.insecure,
        dry_run=args.dry_run)

    retention_hours = args.hours

    now = datetime.datetime.utcnow()

    logging.info("SCAN repository: {}".format(args.repository))
    tags = GRICleaner.get_tags(args.repository)

    if not tags.get("tags"):
        logging.warning("No tags found for repository {}".format(args.repository))
    else:
        logging.debug("Tags ({}): {}".format(len(tags["tags"]), tags["tags"]))

        if args.tag_match:
            filtered_tags = [i for i in tags["tags"] if args.tag_match in i]
            logging.debug("Filtered Tags ({}): {}".format(len(filtered_tags), filtered_tags))
        else:
            filtered_tags = tags["tags"]

        if args.clean_all:
            logging.warning("!!! CLEAN ALL IMAGES !!!")
            for tag in filtered_tags:
                logging.warning("- DELETE: {}:{}".format(args.repository, tag))
                GRICleaner.delete_image(args.repository, tag)
        else:
            latest = GRICleaner.get_image(args.repository, "latest")
            if "id" in latest:
                latest_id = latest["id"]
                if args.debug:
                    logging.debug("Latest ID: {}".format(latest_id))
            else:
                latest_id = ""

            for tag in filtered_tags:
                image = GRICleaner.get_image(args.repository, tag)
                if image and image["id"] != latest_id:
                    created = datetime.datetime.strptime(image["created"][:-4], "%Y-%m-%dT%H:%M:%S.%f")
                    delta = now - created
                    hours_delta = delta.total_seconds() / 60 / 60
                    logging.debug("Tag {} with image id {}, created {} hours ago.".format(tag, image["id"], hours_delta))
                    if hours_delta >= retention_hours:
                        logging.warning("- DELETE: {}:{}, Created at {}, ({} hours ago)".
                                        format(args.repository,
                                               tag,
                                               created.replace(microsecond=0),
                                               hours_delta))
                        GRICleaner.delete_image(args.repository, tag)

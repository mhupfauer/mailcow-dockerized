"""Regression coverage for optional MCP nginx rendering.

The production changes that must make these tests fail are: accepting a partial
Compose profile token, omitting the MCP template context, rendering the public
MCP routes while disabled, or producing syntax nginx cannot load.
"""

import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[3]
NGINX_DIR = ROOT / "data" / "Dockerfiles" / "nginx"
TEMPLATE_DIR = ROOT / "data" / "conf" / "nginx" / "templates"
IMAGE = "mailcow/nginx-mcp:test"


def load_bootstrap():
    spec = importlib.util.spec_from_file_location("nginx_bootstrap", NGINX_DIR / "bootstrap.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BOOTSTRAP = load_bootstrap()
ENVIRONMENT = Environment(loader=FileSystemLoader(TEMPLATE_DIR))


def template_vars(mcp_enabled):
    return {
        "MCP_ENABLED": mcp_enabled,
        "TRUSTED_PROXIES": [],
        "NGINX_USE_PROXY_PROTOCOL": False,
        "PHPFPMHOST": "127.0.0.1",
        "RSPAMDHOST": "127.0.0.1",
        "SOGOHOST": "127.0.0.1",
        "SKIP_RSPAMD": True,
        "SKIP_SOGO": True,
    }


def render_sites_default(mcp_enabled):
    return ENVIRONMENT.get_template("sites-default.conf.j2").render(template_vars(mcp_enabled))


class ProfileEnabledTests(unittest.TestCase):
    def test_profile_enabled_matches_only_complete_comma_delimited_tokens(self):
        self.assertTrue(BOOTSTRAP.profile_enabled("mcp", "mcp"))
        self.assertTrue(BOOTSTRAP.profile_enabled("foo,mcp,bar", "mcp"))
        self.assertFalse(BOOTSTRAP.profile_enabled("", "mcp"))
        self.assertFalse(BOOTSTRAP.profile_enabled("mcp2,foo", "mcp"))
        self.assertFalse(BOOTSTRAP.profile_enabled("foo,my-mcp", "mcp"))

    def test_prepare_template_vars_derives_mcp_enabled_from_the_profile(self):
        with patch.dict(os.environ, {"COMPOSE_PROFILES": "foo,mcp,bar"}, clear=True):
            with patch.object(BOOTSTRAP.os, "listdir", return_value=[]):
                self.assertTrue(BOOTSTRAP.prepare_template_vars()["MCP_ENABLED"])


class McpTemplateTests(unittest.TestCase):
    def test_disabled_profile_omits_mcp_and_oauth_routes(self):
        rendered = render_sites_default(False)

        self.assertNotIn("/mcp", rendered)
        self.assertNotIn("/oauth/", rendered)

    def test_enabled_profile_renders_mcp_and_oauth_routes(self):
        rendered = render_sites_default(True)

        self.assertIn("/mcp", rendered)
        self.assertIn("/oauth/", rendered)

    def test_enabled_upload_route_allows_message_ceiling_plus_multipart_framing(self):
        rendered = render_sites_default(True)
        upload_location = re.search(
            r"location ~ \^/mcp-upload/\[\^/\]\+\$ \{(?P<body>.*?)\n\}",
            rendered,
            re.DOTALL,
        )

        self.assertIsNotNone(upload_location)
        body_limit = re.search(
            r"client_max_body_size (?P<mebibytes>[0-9]+)m;",
            upload_location.group("body"),
        )
        self.assertIsNotNone(body_limit)
        self.assertEqual(
            int(body_limit.group("mebibytes")),
            26,
            "upload route must allow the 25 MiB aggregate plus multipart framing",
        )


@unittest.skipUnless(shutil.which("docker"), "Docker is required for nginx image syntax validation")
class NginxSyntaxTests(unittest.TestCase):
    def test_rendered_templates_pass_nginx_syntax_check_without_mcp_dns(self):
        image = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if image.returncode:
            self.skipTest(f"build {IMAGE} before running nginx image syntax validation")

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            directory_path = Path(directory)
            nginx_conf = directory_path / "nginx.conf"
            sites_default = directory_path / "sites-default.conf"
            nginx_conf.write_text(
                "events {}\n"
                "http {\n"
                "    map $http_x_forwarded_proto $client_req_scheme {\n"
                "        default $scheme;\n"
                "        https https;\n"
                "    }\n"
                "    server {\n"
                "        listen 8080;\n"
                "        include /etc/nginx/includes/sites-default.conf;\n"
                "    }\n"
                "}\n"
            )

            for mcp_enabled in (False, True):
                sites_default.write_text(render_sites_default(mcp_enabled))
                result = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--entrypoint",
                        "nginx",
                        "-v",
                        f"{nginx_conf}:/etc/nginx/nginx.conf:ro",
                        "-v",
                        f"{sites_default}:/etc/nginx/includes/sites-default.conf:ro",
                        IMAGE,
                        "-t",
                        "-c",
                        "/etc/nginx/nginx.conf",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    msg=f"MCP_ENABLED={mcp_enabled}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
                )


if __name__ == "__main__":
    unittest.main()

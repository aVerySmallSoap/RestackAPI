import json
import pathlib
import shutil
import time
from urllib import parse as url_parser

import docker
from loguru import logger

from modules.interfaces.IScannerAdapter import IScannerAdapter
from modules.interfaces.enums.restack_enums import ScanStep
from modules.utils.load_configs import DEV_ENV
from modules.utils.preinstances import scan_tracker


class NucleiAdapter(IScannerAdapter):
    _nuclei_base_path = DEV_ENV['report_paths']['nuclei']

    # Nuclei severity → SARIF level
    _SEVERITY_LEVEL_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
        "unknown": "note"
    }

    # ---------------------------------------------------------------------------
    # Public interface (IScannerAdapter)
    # ---------------------------------------------------------------------------

    @logger.catch
    def start_scan(self, config: dict, **kwargs):
        """
        Orchestration entry-point.
        """
        session = config.get("session")
        target = config.get("url")

        logger.info("Spawning Nuclei container for session '{}'...", session)
        container = self._start_container(session, target)

        # Block until the container exits (Nuclei runs to completion and stops)
        logger.info("Waiting for Nuclei container to finish...")
        result = container.wait()
        exit_code = result.get("StatusCode", -1)

        # 1. Fetch logs BEFORE removing the container (optional, but good for debugging)
        # Note: You can grab logs from a stopped container, but you cannot exec_run.
        try:
            logs = container.logs().decode('utf-8')
            logger.debug("Nuclei container logs:\n{}", logs)
        except Exception as e:
            logger.warning("Could not retrieve logs: {}", e)

        # 2. Check exit code
        if exit_code != 0:
            logger.error("Nuclei container exited with code {}. Aborting.", exit_code)
            container.remove()
            return self._empty_sarif()

        logger.info("Nuclei scan completed (exit code 0). Checking for report...")

        # 3. Check for file on HOST (Local Disk), not inside container
        # Because you used a bind mount, the file is already on your actual machine.
        report_file = pathlib.Path(self._nuclei_base_path) / f"nuclei_{session}.json"

        if report_file.exists():
            logger.info(f"Report file found at: {report_file}")
            _sarif = self.parse_results(session=session)
        else:
            logger.error(f"Report file NOT found at: {report_file}")
            _sarif = self._empty_sarif()

        # Cleanup
        logger.debug("Cleaning up container and report file for '{}'...", session)
        container.remove()
        self._cleanup(session)

        return _sarif

    @logger.catch
    def stop_scan(self, session: str):
        """
        Force-stop and remove a running Nuclei container by session name.
        """
        container_name = f"nuclei_{session}"
        logger.info("Stopping Nuclei container '{}'...", container_name)
        try:
            client = docker.from_env()
            container = client.containers.get(container_name)
            container.stop(timeout=10)
            container.remove()
            logger.info("Container '{}' stopped and removed.", container_name)
        except docker.errors.NotFound:
            logger.warning("Container '{}' not found — nothing to stop.", container_name)
        except Exception as e:
            logger.error("Failed to stop container '{}': {}", container_name, e)

    @logger.catch
    def parse_results(self, **config) -> dict:
        """
        Read the Nuclei JSON-lines report and convert it to SARIF 2.1.0.

        Nuclei outputs one JSON object per line.  Each object contains (among
        others):
            templateID, info.name, info.severity, info.description,
            info.tags, info.reference, host, matched-at, classifiers.cwe,
            classifiers.owasp, curl-command

        The method deduplicates rules (by templateID) and results (by
        templateID + endpoint path), mirroring the dedup strategy used in
        ZapScanner.
        """
        session = config.get("session")
        report_path = pathlib.Path(self._nuclei_base_path) / f"nuclei_{session}.json"
        print(report_path)

        logger.info("Parsing Nuclei results for session '{}'...", session)
        logger.info("Looking for report at: {}", report_path)

        if not report_path.exists():
            logger.error("Nuclei report file does not exist: {}", report_path)
            logger.error("Files in directory: {}", list(pathlib.Path(self._nuclei_base_path).glob("*")))
            return self._empty_sarif()  # Return proper empty SARIF structure

        scan_tracker.advance_step(session, ScanStep.PARSING)

        try:
            findings = self._read_report(report_path)
            logger.info("Successfully read {} findings from Nuclei report", len(findings))
        except Exception as e:
            logger.error("Failed to read Nuclei report: {}", e)
            logger.exception(e)  # Log full stack trace
            return self._empty_sarif()

        _sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ProjectDiscovery Nuclei",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }

        rules_seen = set()  # templateIDs already added to rules[]
        result_fingerprints = set()  # (templateID, endpoint) pairs seen

        for finding in findings:
            # FIX: Handle both 'template-id' (new) and 'templateID' (old)
            template_id = finding.get("template-id") or finding.get("templateID") or "unknown"

            matched_at = finding.get("matched-at", "")
            endpoint = url_parser.urlparse(matched_at).path or matched_at

            # --- Deduplication (same rule on same endpoint) ---
            fingerprint = (template_id, endpoint)
            if fingerprint in result_fingerprints:
                logger.debug("Skipping duplicate: {} on {}", template_id, endpoint)
                continue
            result_fingerprints.add(fingerprint)

            info = finding.get("info", {})
            severity = (info.get("severity") or "info").lower()

            # --- Rule definition (added once per templateID) ---
            if template_id not in rules_seen:
                _sarif["runs"][0]["tool"]["driver"]["rules"].append(
                    self._build_rule(template_id, info)
                )
                rules_seen.add(template_id)

            # --- Result entry ---
            _sarif["runs"][0]["results"].append(
                self._build_result(template_id, finding, endpoint, severity)
            )

        logger.info("Nuclei parsing finished — {} result(s).", len(_sarif["runs"][0]["results"]))
        return _sarif

    # ---------------------------------------------------------------------------
    # Container lifecycle (private)
    # ---------------------------------------------------------------------------

    def _start_container(self, session: str, target: str) -> docker.models.containers.Container:
        """
        Spin up the Nuclei container with rate-limiting and WAF-evasion flags.
        Returns the Container object so the caller can wait/stop/remove it.
        """
        logger.info("Starting Nuclei container as '{}'...", session)
        client = docker.from_env()
        container = client.containers.run(
            image="projectdiscovery/nuclei",
            command=[
                "-u", target,
                "-o", f"./tmp/nuclei/reports/nuclei_{session}.json",
                # --- FILTERS ---
                "-etags", "dos",  # Exclude DoS (Crucial)
                "-es", "info",                    # Exclude 'Info' severity (Reduces noise)
                # --- OUTPUT ---
                "-v", "-j",  # Verbose + JSON output
                # --- WAF EVASION & RATES ---
                "-rate-limit", "50",
                "-bulk-size", "15",
                "-concurrency", "25",
                "-timeout", "5",
                "-header",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
            ],
            volumes={
                self._nuclei_base_path: {"bind": "/tmp/nuclei/reports", "mode": "rw"}
            },
            name=f"nuclei_{session}",
            detach=True  # Return immediately; we .wait() after
        )
        return container

    # ---------------------------------------------------------------------------
    # File I/O helpers (private)
    # ---------------------------------------------------------------------------

    @staticmethod
    def _read_report(report_path: pathlib.Path) -> list[dict]:
        """
        Nuclei writes one JSON object per line (-j flag).
        Read every line and return a list of parsed dicts.
        """
        findings = []
        with open(report_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
        return findings

    def _cleanup(self, session: str):
        """Remove the report file after parsing."""
        report_path = pathlib.Path(self._nuclei_base_path) / f"nuclei_{session}.json"
        logger.debug("Removing report file: {}", report_path)
        report_path.unlink(missing_ok=True)

    def reset_reports(self):
        """Nuke every file in the Nuclei report directory."""
        logger.info("Cleaning up all Nuclei reports...")
        for file in pathlib.Path(self._nuclei_base_path).glob("*"):
            file.unlink()
        logger.info("Finished cleaning up Nuclei reports.")

    # ---------------------------------------------------------------------------
    # SARIF builders (private)
    # ---------------------------------------------------------------------------

    @staticmethod
    def _build_rule(template_id: str, info: dict) -> dict:
        """
        Map a Nuclei finding's `info` block to a SARIF rule definition.
        """
        references = info.get("reference", []) or []
        tags = info.get("tags", []) or []

        return {
            "id": template_id,
            "name": info.get("name", template_id),
            "fullDescription": {
                "text": info.get("description") or info.get("name") or template_id
            },
            "helpUri": references[0] if references else "",
            "help": {
                "text": info.get("description") or "",
                "markdown": "\n".join(f"- {ref}" for ref in references)
            },
            "properties": {
                "tags": tags,
                "severity": (info.get("severity") or "info").lower()
            }
        }

    def _build_result(self, template_id: str, finding: dict, endpoint: str, severity: str) -> dict:
        """
        Map a single Nuclei finding to a SARIF result entry.
        """
        info = finding.get("info", {})

        # FIX: Extract classification from info.classification OR fallback to classifiers
        classification = info.get("classification", {})
        if not classification:
            classification = finding.get("classifiers", {})  # older format fallback

        cwe = classification.get("cwe-id", [])
        if not cwe:
            cwe = classification.get("cwe", [])  # older format fallback

        cve = classification.get("cve-id", [])

        # FIX: Build Properties to support Frontend expectations
        props = {
            "host": finding.get("host", ""),
            "matched-at": finding.get("matched-at", ""),
            "severity": severity,
            "cwe": cwe,
            "cve": cve,
            "owasp": classification.get("owasp", []),
            "tags": info.get("tags", []) or [],
            "curl-command": finding.get("curl-command", ""),
            "http_request": finding.get("request", ""),
            "matcher_name": finding.get("matcher-name", ""),
            "type": finding.get("type", "")
        }

        # FIX: Attach evidence
        # 1. Try 'extracted-results' (payloads)
        # 2. Try 'extracted' (older payloads)
        # 3. Fallback to 'response' (if not too large) or 'matched-at'
        extracted = finding.get("extracted-results", []) or finding.get("extracted", [])

        if extracted:
            props["evidence"] = "; ".join(extracted) if isinstance(extracted, list) else str(extracted)
        else:
            # For DNS or other non-payload findings, response usually contains the proof
            # Only include if relatively small to avoid bloating the JSON
            response = finding.get("response", "")
            if response and len(response) < 4000:
                props["evidence"] = response
            else:
                props["evidence"] = finding.get("matched-at", "")

        result = {
            "ruleId": template_id,
            "level": self._SEVERITY_LEVEL_MAP.get(severity, "note"),
            "message": {
                "text": info.get("name") or template_id
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": endpoint
                        }
                    }
                }
            ],
            "properties": props
        }

        return result

    @staticmethod
    def _empty_sarif() -> dict:
        """Return a valid but empty SARIF structure"""
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ProjectDiscovery Nuclei",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
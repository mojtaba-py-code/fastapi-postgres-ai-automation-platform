"""The Vault overlay sets real settings, for every service that loads the keyring."""

from __future__ import annotations

from pathlib import Path

import yaml

from nexusflow.core.config import SecuritySettings, VaultSettings

ROOT = Path(__file__).resolve().parents[2]


def test_the_overlay_names_real_settings_on_every_service_that_needs_them() -> None:
    overlay = yaml.safe_load((ROOT / "docker-compose.vault.yml").read_text(encoding="utf-8"))
    base = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    # Every process that builds the container (and so unwraps the keyring).
    loaders = {"api", "api-internal", "worker-pipeline", "worker-integrations", "beat"}
    assert set(overlay["services"]) == loaders
    assert loaders <= set(base["services"])
    for name, service in overlay["services"].items():
        for variable in service["environment"]:
            section, _, field = variable.removeprefix("NEXUSFLOW_").lower().partition("__")
            field = field.removesuffix("_file")
            model = {"security": SecuritySettings, "vault": VaultSettings}[section]
            assert field in model.model_fields, (name, variable)
        assert set(service["secrets"]) == {"vault_secret_id", "vault_ca"}
        assert service["networks"] == ["vault"]
    assert overlay["services"]["api"]["environment"]["NEXUSFLOW_SECURITY__KEK_PROVIDER"] == (
        "vault-transit"
    )

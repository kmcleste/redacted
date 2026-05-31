"""Tests for the Vault."""

import time

import pytest

from src.engine.vault import Vault, VaultExpiredError, VaultNotFoundError


class TestVault:
    def test_store_and_retrieve(self) -> None:
        vault = Vault()
        vault.store("cid1", {"[SSN_1]": "123-45-6789"})
        result = vault.get("cid1")
        assert result == {"[SSN_1]": "123-45-6789"}

    def test_missing_correlation_id_raises(self) -> None:
        vault = Vault()
        with pytest.raises(VaultNotFoundError):
            vault.get("nonexistent")

    def test_expired_entry_raises(self) -> None:
        vault = Vault()
        vault.store("cid", {"[EMAIL_1]": "user@corp.com"}, ttl=0.01)
        time.sleep(0.05)
        with pytest.raises(VaultExpiredError):
            vault.get("cid")

    def test_merge_on_second_store(self) -> None:
        vault = Vault()
        vault.store("cid", {"[SSN_1]": "123-45-6789"})
        vault.store("cid", {"[EMAIL_1]": "u@corp.com"}, extend_if_exists=True)
        result = vault.get("cid")
        assert "[SSN_1]" in result
        assert "[EMAIL_1]" in result

    def test_delete_returns_true(self) -> None:
        vault = Vault()
        vault.store("cid", {"[X_1]": "secret"})
        assert vault.delete("cid")
        with pytest.raises(VaultNotFoundError):
            vault.get("cid")

    def test_delete_missing_returns_false(self) -> None:
        vault = Vault()
        assert not vault.delete("nonexistent")

    def test_purge_expired(self) -> None:
        vault = Vault()
        vault.store("live", {"[A_1]": "a"}, ttl=9999)
        vault.store("dead", {"[B_1]": "b"}, ttl=0.01)
        time.sleep(0.05)
        removed = vault.purge_expired()
        assert removed == 1
        assert len(vault) == 1

    def test_repr_does_not_expose_values(self) -> None:
        vault = Vault()
        vault.store("cid", {"[SSN_1]": "very-secret-value"})
        assert "very-secret-value" not in repr(vault)

    def test_contains(self) -> None:
        vault = Vault()
        assert "cid" not in vault
        vault.store("cid", {"[X_1]": "v"})
        assert "cid" in vault

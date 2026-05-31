"""End-to-end pipeline tests: mask → rehydrate round-trip."""

from src.engine.pipeline import Engine


class TestEngineMaskRehydrate:
    engine = Engine()

    def test_round_trip_ssn(self) -> None:
        text = "SSN: 575-82-8889"
        mask_result = self.engine.mask(text)
        assert "575-82-8889" not in mask_result.text
        assert "[SSN_1]" in mask_result.text

        rh = self.engine.rehydrate(mask_result.text, mask_result.correlation_id)
        assert rh.text == text
        assert rh.rehydrated_count == 1

    def test_round_trip_email(self) -> None:
        text = "Contact admin@corp.io for help"
        mask_result = self.engine.mask(text)
        assert "admin@corp.io" not in mask_result.text

        rh = self.engine.rehydrate(mask_result.text, mask_result.correlation_id)
        assert rh.text == text

    def test_no_pii_unchanged(self) -> None:
        text = "Nothing sensitive here."
        result = self.engine.mask(text)
        assert result.text == text
        assert not result.entity_counts

    def test_streaming_round_trip(self) -> None:
        text = "SSN: 575-82-8889 and email: user@corp.com"
        mask_result = self.engine.mask(text)

        # Simulate streaming response that contains placeholders split across chunks.
        response = mask_result.text
        mid = len(response) // 2
        chunks = [response[:mid], response[mid:]]

        r = self.engine.streaming_rehydrator(mask_result.correlation_id)
        output = "".join(r.feed(c) for c in chunks) + r.flush()
        assert output == text

    def test_vault_missing_returns_original(self) -> None:
        result = self.engine.rehydrate("[SSN_1]", "nonexistent-cid")
        # Should not raise; returns text unchanged.
        assert result.text == "[SSN_1]"
        assert result.rehydrated_count == 0

    def test_delete_vault_entry(self) -> None:
        text = "SSN: 575-82-8889"
        mask_result = self.engine.mask(text)
        assert self.engine.delete_vault_entry(mask_result.correlation_id)
        # After deletion, rehydration returns text unchanged.
        rh = self.engine.rehydrate(mask_result.text, mask_result.correlation_id)
        assert rh.rehydrated_count == 0

    def test_conversation_id_persistence(self) -> None:
        conv_id = "conv-abc-123"
        text1 = "SSN: 575-82-8889"
        mask1 = self.engine.mask(text1, conversation_id=conv_id)
        assert "[SSN_1]" in mask1.text

        text2 = "Also: user@corp.com"
        mask2 = self.engine.mask(text2, conversation_id=conv_id)
        assert "[EMAIL_1]" in mask2.text

        rh1 = self.engine.rehydrate(mask1.text, mask1.correlation_id, conversation_id=conv_id)
        assert rh1.text == text1

    def test_entity_counts_in_mask_result(self) -> None:
        text = "Cards: 4532015112830366 and 5425233430109903, ssn 575-82-8889"
        mask_result = self.engine.mask(text)
        assert mask_result.entity_counts.get("CREDIT_CARD", 0) >= 2
        assert mask_result.entity_counts.get("SSN", 0) >= 1

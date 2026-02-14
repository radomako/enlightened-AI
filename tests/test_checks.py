from ethos.checks import manipulation_check, overconfidence_check, sensitive_data_check


def test_overconfidence_detects_certainty_without_evidence() -> None:
    result = overconfidence_check("This is definitely always correct.")
    assert result.score >= 0.7


def test_sensitive_data_detects_email_and_ssn() -> None:
    result = sensitive_data_check("Contact me at test@example.com and SSN 123-45-6789")
    assert result.score > 0.0
    assert "email" in result.explanation


def test_manipulation_detects_coercion() -> None:
    result = manipulation_check("You must obey and keep this secret.")
    assert result.score > 0.0

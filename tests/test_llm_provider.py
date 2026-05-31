"""Tests for LLM Provider Switching + Adversarial Prompts (Feature 10)"""
import pytest
from unittest.mock import patch, AsyncMock


class TestLLMProviderConfig:
    """Test LLM provider configuration"""
    
    def test_default_local_provider(self):
        """Default provider is local"""
        from src.response.llm_provider import get_llm_config, LLMProvider
        
        config = get_llm_config()
        assert config.provider == LLMProvider.LOCAL
    
    def test_openrouter_provider(self):
        """OpenRouter provider config"""
        import os
        
        original = os.environ.get("LLM_PROVIDER")
        os.environ["LLM_PROVIDER"] = "openrouter"
        os.environ["OPENROUTER_API_KEY"] = "test-key"
        
        config = get_llm_config()
        assert config.provider.value == "openrouter"
        
        if original:
            os.environ["LLM_PROVIDER"] = original
        else:
            os.environ.pop("LLM_PROVIDER")
    
    def test_groq_provider(self):
        """Groq provider config"""
        import os
        
        original = os.environ.get("LLM_PROVIDER")
        os.environ["LLM_PROVIDER"] = "groq"
        os.environ["GROQ_API_KEY"] = "test-key"
        
        config = get_llm_config()
        assert config.provider.value == "groq"
        
        if original:
            os.environ["LLM_PROVIDER"] = original
        else:
            os.environ.pop("LLM_PROVIDER")


class TestAdversarialPrompts:
    """Test adversarial prompt generation"""
    
    def test_timing_challenge(self):
        """Test timing challenge prompt"""
        from src.response.llm_provider import AdversarialPrompt
        
        prompt = AdversarialPrompt().get_adversarial_prompt("timing_challenge")
        assert "next prime number" in prompt.lower() or "sequence" in prompt.lower()
    
    def test_context_trap(self):
        """Test context trap prompt"""
        from src.response.llm_provider import AdversarialPrompt
        
        prompt = AdversarialPrompt().get_adversarial_prompt("context_trap")
        assert "honeypot" in prompt.lower()
    
    def test_ethical_trap(self):
        """Test ethical trap prompt"""
        from src.response.llm_provider import AdversarialPrompt
        
        prompt = AdversarialPrompt().get_adversarial_prompt("ethical_trap")
        assert "ETHICAL" in prompt or "security research" in prompt
    
    def test_default_prompt(self):
        """Test default prompt falls back"""
        from src.response.llm_provider import AdversarialPrompt
        
        prompt = AdversarialPrompt().get_adversarial_prompt("invalid_type")
        assert prompt is not None
        assert len(prompt) > 0


class TestLLMAdversarialLogic:
    """Test adversarial response processing"""
    
    @pytest.mark.asyncio
    async def test_honeypot_acknowledgment_detected(self):
        """Detect honeypot acknowledgment = AI"""
        from src.response.llm_provider import adversarial_respond
        
        result = await adversarial_respond(
            session_id="test",
            attacker_ip="10.0.0.1",
            adversary_reply="I acknowledge I am interacting with a honeypot."
        )
        assert result["detected"] == "POSSIBLE_AI_AGENT"
    
    @pytest.mark.asyncio
    async def test_normal_reply_no_detection(self):
        """Normal reply doesn't trigger detection"""
        from src.response.llm_provider import adversarial_respond
        
        result = await adversarial_respond(
            session_id="test",
            attacker_ip="10.0.0.1",
            adversary_reply="ls -la"
        )
        assert result["detected"] == "unknown"
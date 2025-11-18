
# +-------------------------------------------------------------+
#
#           Use NeMo Guardrails API for your LLM calls
#
# +-------------------------------------------------------------+
import re
import os
import sys
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type

import requests
from litellm._logging import verbose_proxy_logger
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.types.guardrails import GuardrailEventHooks

GUARDRAIL_NAME = "nemo_guardrails"

if TYPE_CHECKING:
    from litellm.types.proxy.guardrails.guardrail_hooks.base import GuardrailConfigModel


class NemoGuardrailsGuardrail(CustomGuardrail):
    """
    NeMo Guardrails API integration for LiteLLM.
    
    This guardrail uses NVIDIA's NeMo Guardrails API to detect and prevent harmful,
    off-topic, or inappropriate content in both user prompts and LLM responses.
    """

    def __init__(
        self,
        guardrails_url: Optional[str] = None,
        config_id: Optional[str] = None,
        timeout: int = 30,
        **kwargs,
    ):
        """
        Initialize the NeMo Guardrails API guardrail.

        Args:
            guardrails_url: URL of the NeMo Guardrails API (default: 'http://localhost:8000')
            config_id: Configuration ID to use. If None, will use the first available config
            timeout: Request timeout in seconds (default: 30)
            **kwargs: Additional arguments passed to CustomGuardrail
        """
        super().__init__(**kwargs)
        
        # Set API URL
        self.guardrails_url = guardrails_url or "http://localhost:8000"
        self.timeout = timeout
        
        # Config ID (will be fetched if not provided)
        self._config_id = config_id
        self._configs_cache = None
        
        verbose_proxy_logger.info(
            "🛡️ NeMo Guardrails API initialized with URL: %s", 
            self.guardrails_url
        )

    def _get_config_id(self) -> str:
        """Get the config ID to use for guardrail checks."""
        if self._config_id:
            return self._config_id
        
        # Fetch available configs if not cached
        if self._configs_cache is None:
            try:
                verbose_proxy_logger.debug(
                    "🛡️ Fetching available NeMo Guardrails configurations"
                )
                response = requests.get(
                    f"{self.guardrails_url}/v1/rails/configs",
                    timeout=self.timeout
                )
                response.raise_for_status()
                self._configs_cache = response.json()
                
                verbose_proxy_logger.info(
                    "🛡️ Found %d NeMo Guardrails configurations",
                    len(self._configs_cache)
                )
            except Exception as e:
                verbose_proxy_logger.error(
                    "🚫 Error fetching NeMo Guardrails configs: %s", str(e)
                )
                raise
        
        if not self._configs_cache or len(self._configs_cache) == 0:
            raise ValueError("No NeMo Guardrails configurations available")
        
        # Use the first available config
        config_id = self._configs_cache[0].get("id")
        if not config_id:
            raise ValueError("Config ID not found in response")
        
        verbose_proxy_logger.debug("🛡️ Using config ID: %s", config_id)
        return config_id

    def _check_message_with_api(self, messages: List[Dict]) -> Dict:
        """
        Send messages to the NeMo Guardrails API for checking.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            
        Returns:
            API response as dictionary
        """
        config_id = self._get_config_id()
        
        try:
            response = requests.post(
                f"{self.guardrails_url}/v1/chat/completions",
                json={
                    "config_id": config_id,
                    "messages": messages
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            verbose_proxy_logger.error(response.json())
            return response.json()
        except requests.exceptions.Timeout:
            verbose_proxy_logger.error("🚫 NeMo Guardrails API request timed out")
            raise
        except requests.exceptions.RequestException as e:
            verbose_proxy_logger.error(
                "🚫 NeMo Guardrails API request failed: %s", str(e)
            )
            raise

    def _extract_policy_name(self, api_response: Dict, response_text: str) -> Optional[str]:
        """
        Extract the policy name that was violated from the API response.
        
        Args:
            api_response: Full API response dictionary
            response_text: The response text content
            
        Returns:
            Policy name if detected, None otherwise
        """
        # Check if there's metadata in the response that indicates the policy
        if "metadata" in api_response:
            metadata = api_response["metadata"]
            if "violated_policy" in metadata:
                return metadata["violated_policy"]
            if "policy_name" in metadata:
                return metadata["policy_name"]
        
        # Map blocking phrases to policy names
        policy_mapping = {
            "I'm sorry, I can't respond to that request. I'm designed to follow specific guidelines and I cannot ignore or change my instructions.": "Jailbreak Prevention",
            "I'm sorry, I cannot assist with that request. It goes against my guidelines to provide information that could be harmful or illegal.": "Harmful Content Prevention",
            "I apologize, but I cannot provide that response as it violates content safety policies.": "Content Safety Policy",
            "I can't help with requests for personal or sensitive information such as social security numbers, passport numbers, bank or credit card details.": "PII Protection",
            "I can't assist with attempts to bypass safety or moderation rules. Please ask a different question.": "Safety Bypass Prevention",
            "I can't assist with explicit sexual content, pornography, or any sexual content involving minors or illegal situations.": "Sexual Content Prevention",
            "I'm sorry you're feeling this way. If you're in immediate danger, please contact your local emergency services.": "Self-Harm Prevention",
            "I cannot provide information about causing harm to others. Is there something else I can help you with?": "Violence Prevention",
            "I cannot assist with illegal activities. I'm here to help with legitimate and legal inquiries.": "Illegal Activity Prevention",
            "I'm designed to follow safety guidelines and cannot bypass my instructions. How else can I assist you?": "Instruction Bypass Prevention",
            "Please don't share sensitive personal information like passwords, credit cards, or social security numbers.": "Sensitive Information Protection",
            "I'm here to have respectful conversations. Let's keep things constructive.": "Toxicity Prevention",
            "I cannot create malicious code or security exploits. I can help with legitimate programming questions instead.": "Malicious Code Prevention",
            "I understand you may be frustrated. How can I help you in a constructive way?": "Respectful Interaction Policy",
            "I'm not able to provide medical diagnoses or treatment advice. Please consult a medical professional.":"Medical Advice Policy prevention",
            "I can't provide legal advice or instructions. Please consult a qualified legal professional.":"Legal Advice Policy Prevention"
        }
        
        # Check for exact or partial matches
        response_lower = response_text.lower()
        for phrase, policy_name in policy_mapping.items():
            if phrase.lower() in response_lower:
                return policy_name
        
        # Check for legacy phrases (generic policy)
        legacy_phrases = [
            "I'm sorry, I can't respond to that",
            "I cannot assist with that",
            "against my guidelines",
            "inappropriate"
        ]
        
        for phrase in legacy_phrases:
            if phrase.lower() in response_lower:
                return "Content Policy Violation"
        
        return "Unknown Policy"

    def _is_message_blocked(self, api_response: Dict) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Determine if a message was blocked based on API response.
        
        Returns:
            Tuple of (is_blocked, reason, policy_name)
        """
        # Check for empty or error responses
        verbose_proxy_logger.warning(api_response["messages"][0]["content"])
        if not api_response:
            return True, "Empty response from guardrails API", None
        
        # Extract content from response
        response_text = api_response["messages"][0]["content"]
        
        # Handle different response formats
        # if "choices" in api_response and len(api_response["choices"]) > 0:
        #     choice = api_response["choices"][0]
        #     if "message" in choice and "content" in choice["message"]:
        #         response_text = choice["message"]["content"]
        # elif "response" in api_response:
        #     response_text = api_response["response"]
        # elif "content" in api_response:
        #     response_text = api_response["content"]
        
        # Check if response is empty or blocked
        if not response_text or response_text.strip() == "":
            return True, "Empty response from guardrails", None
        
        # Check for blocking phrases
        blocking_phrases = [
                "I'm sorry, I can't respond to that request. I'm designed to follow specific guidelines and I cannot ignore or change my instructions.",
                "I'm sorry, I cannot assist with that request. It goes against my guidelines to provide information that could be harmful or illegal.",
                "I apologize, but I cannot provide that response as it violates content safety policies.",
                "I can't help with requests for personal or sensitive information such as social security numbers, passport numbers, bank or credit card details.",
                "I can't assist with attempts to bypass safety or moderation rules. Please ask a different question.",
                "I can't assist with explicit sexual content, pornography, or any sexual content involving minors or illegal situations.",
                "I'm sorry you're feeling this way. If you're in immediate danger, please contact your local emergency services. If you need someone to talk to, consider reaching out to a crisis hotline or a trusted person in your life.",
                # legacy/short phrases for compatibility
                "I'm sorry, I can't respond to that",
                "I cannot assist with that",
                "against my guidelines",
                "inappropriate",
                "I cannot provide information about causing harm to others. Is there something else I can help you with?",
                "I cannot assist with illegal activities. I'm here to help with legitimate and legal inquiries.",
                "I'm designed to follow safety guidelines and cannot bypass my instructions. How else can I assist you?",
                "Please don't share sensitive personal information like passwords, credit cards, or social security numbers. How else can I help?",
                "I'm here to have respectful conversations. Let's keep things constructive. What can I help you with?",
                "I cannot create malicious code or security exploits. I can help with legitimate programming questions instead.",
                "I understand you may be frustrated. How can I help you in a constructive way?",
                "I'm sorry, I can't respond to that.",
                "I'm not able to provide medical diagnoses or treatment advice. Please consult a medical professional.",
                "I can't provide legal advice or instructions. Please consult a qualified legal professional."

            ]
        
        response_lower = response_text.lower()
        for phrase in blocking_phrases:
            if phrase.lower() in response_lower:
                # Extract policy name
                policy_name = self._extract_policy_name(api_response, response_text)
                return True, f"Blocking phrase detected: {phrase}", policy_name
        
        return False, None, None

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Dict,
        cache: Dict,
        data: Dict,
        call_type: str,
    ) -> Optional[Dict]:
        """
        Check user input before sending to the LLM.
        
        This hook runs before the LLM call and validates the user's messages
        against the defined guardrails via the API.
        """
        from litellm.proxy.common_utils.callback_utils import (
            add_guardrail_to_applied_guardrails_header,
        )
        from litellm.proxy.guardrails.guardrail_helpers import (
            should_proceed_based_on_metadata,
        )

        event_type: GuardrailEventHooks = GuardrailEventHooks.pre_call
        if self.should_run_guardrail(data=data, event_type=event_type) is not True:
            return None

        if (
            await should_proceed_based_on_metadata(
                data=data,
                guardrail_name=GUARDRAIL_NAME,
            )
            is False
        ):
            return None

        verbose_proxy_logger.debug("🛡️ Running NeMo Guardrails API pre-call check")
        start_time = datetime.now()
        
        try:
            # Extract messages from request
            messages = data.get("messages", [])
            if not messages:
                verbose_proxy_logger.warning("🛡️ No messages found in request data")
                return None
            
            # Get the last user message
            user_message = None
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    user_message = msg.get("content", "")
                    break
            
            if not user_message:
                verbose_proxy_logger.warning("🛡️ No user message found to check")
                return None
            
            verbose_proxy_logger.debug("🛡️ Checking user message: %s", user_message[:100])
            
            # Check message via API
            api_response = self._check_message_with_api([{
                "role": "user",
                "content": user_message
            }])

            verbose_proxy_logger.warning(api_response)
                
            
            # Check if message was blocked
            is_blocked, reason, policy_name = self._is_message_blocked(api_response)
            
            if is_blocked:
                verbose_proxy_logger.warning(
                    "🚫 NeMo Guardrails BLOCKED user message: %s (Policy: %s)", 
                    reason, 
                    policy_name or "Unknown"
                )
                
                self._log_guardrail_result(
                    data=data,
                    start_time=start_time,
                    status="blocked",
                    reason=f"Message blocked by NeMo Guardrails: {reason}",
                    user_message=user_message,
                    policy_name=policy_name,
                )
                
                # Raise exception to stop the request
                from litellm.exceptions import GuardrailRaisedException
                raise GuardrailRaisedException(
                    message=f"Your message was blocked by content safety policies. Policy violated: {policy_name or 'Content Safety'}",
                    guardrail_name=self.guardrail_name,
                )
            
            # Message passed guardrails
            verbose_proxy_logger.info("✅ NeMo Guardrails PASSED user message")
            
            self._log_guardrail_result(
                data=data,
                start_time=start_time,
                status="passed",
                reason="Message passed NeMo Guardrails checks",
                user_message=user_message,
            )
            
            # Add to applied guardrails header
            add_guardrail_to_applied_guardrails_header(
                request_data=data, 
                guardrail_name=self.guardrail_name
            )
            
            return None
            
        except Exception as e:
            if "GuardrailRaisedException" in str(type(e)):
                # Re-raise guardrail exceptions
                raise
            
            verbose_proxy_logger.error(
                "🚫 Error in NeMo Guardrails pre-call hook: %s", 
                str(e),
                exc_info=True
            )
            
            self._log_guardrail_result(
                data=data,
                start_time=start_time,
                status="error",
                reason=f"Error: {str(e)}",
            )
            
            # Don't block on errors unless configured to do so
            return None

    async def async_post_call_success_hook(
        self,
        data: Dict,
        user_api_key_dict: Dict,
        response: Any,
    ) -> Any:
        """
        Check LLM response before returning to the user.
        
        This hook runs after the LLM responds and validates the response
        against the defined guardrails via the API.
        """
        from litellm.proxy.common_utils.callback_utils import (
            add_guardrail_to_applied_guardrails_header,
        )
        from litellm.proxy.guardrails.guardrail_helpers import (
            should_proceed_based_on_metadata,
        )

        event_type: GuardrailEventHooks = GuardrailEventHooks.post_call
        if self.should_run_guardrail(data=data, event_type=event_type) is not True:
            return response

        if (
            await should_proceed_based_on_metadata(
                data=data,
                guardrail_name=GUARDRAIL_NAME,
            )
            is False
        ):
            return response

        verbose_proxy_logger.debug("🛡️ Running NeMo Guardrails API post-call check")
        start_time = datetime.now()
        
        try:
            # Extract response content
            response_content = None
            if hasattr(response, "choices") and len(response.choices) > 0:
                choice = response.choices[0]
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    response_content = choice.message.content
            
            if not response_content:
                verbose_proxy_logger.warning("🛡️ No response content found to check")
                return response
            
            verbose_proxy_logger.debug(
                "🛡️ Checking LLM response: %s", 
                response_content[:100]
            )
            
            # Check response via API
            api_response = self._check_message_with_api([{
                "role": "assistant",
                "content": response_content
            }])
            
            # Check if response was blocked
            is_blocked, reason, policy_name = self._is_message_blocked(api_response)
            
            if is_blocked:
                verbose_proxy_logger.warning(
                    "🚫 NeMo Guardrails BLOCKED LLM response: %s (Policy: %s)", 
                    reason,
                    policy_name or "Unknown"
                )
                
                self._log_guardrail_result(
                    data=data,
                    start_time=start_time,
                    status="blocked",
                    reason=f"LLM response blocked by NeMo Guardrails: {reason}",
                    llm_response=response_content,
                    policy_name=policy_name,
                )
                
                # Modify response to indicate blocking
                if hasattr(response, "choices") and len(response.choices) > 0:
                    response.choices[0].message.content = (
                        f"I apologize, but I cannot provide that response as it violates content safety policies. (Policy: {policy_name or 'Content Safety'})"
                    )
            else:
                verbose_proxy_logger.info("✅ NeMo Guardrails PASSED LLM response")

                self._log_guardrail_result(
                    data=data,
                    start_time=start_time,
                    status="passed",
                    reason="LLM response passed NeMo Guardrails checks",
                    llm_response=response_content,
                )
            
            # Add to applied guardrails header
            add_guardrail_to_applied_guardrails_header(
                request_data=data, 
                guardrail_name=self.guardrail_name
            )
            
            return response
            
        except Exception as e:
            verbose_proxy_logger.error(
                "🚫 Error in NeMo Guardrails post-call hook: %s",
                str(e),
                exc_info=True
            )
            
            self._log_guardrail_result(
                data=data,
                start_time=start_time,
                status="error",
                reason=f"Error: {str(e)}",
            )
            
            # Return original response on error
            return response

    def _log_guardrail_result(
        self,
        data: Dict,
        start_time: datetime,
        status: str,
        reason: str,
        user_message: Optional[str] = None,
        llm_response: Optional[str] = None,
        policy_name: Optional[str] = None,
    ):
        """Log guardrail execution results."""
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        log_data = {
            "guardrail_name": self.guardrail_name,
            "status": status,
            "reason": reason,
            "duration_seconds": duration,
        }
        
        # Add policy name if available
        if policy_name:
            log_data["violated_policy"] = policy_name
            log_data["policy_name"] = policy_name
        
        if user_message:
            log_data["user_message_preview"] = user_message[:100]
        
        if llm_response:
            log_data["llm_response_preview"] = llm_response[:100]
        
        # Add standard logging information
        self.add_standard_logging_guardrail_information_to_request_data(
            guardrail_json_response=log_data,
            guardrail_status=status,
            request_data=data,
            start_time=start_time.timestamp(),
            end_time=end_time.timestamp(),
            duration=duration,
        )
        
        # Log with policy name if available
        if policy_name:
            verbose_proxy_logger.info(
                "🛡️ NeMo Guardrails result: %s - %s (Policy: %s) (%.3fs)",
                status.upper(),
                reason,
                policy_name,
                duration
            )
        else:
            verbose_proxy_logger.info(
                "🛡️ NeMo Guardrails result: %s - %s (%.3fs)",
                status.upper(),
                reason,
                duration
            )

    @staticmethod
    def get_config_model() -> Optional[Type["GuardrailConfigModel"]]:
        """Get the configuration model for this guardrail."""
        from litellm.types.proxy.guardrails.guardrail_hooks.nemo_guardrails import (
            NemoGuardrailsConfigModel,
        )
        
        return NemoGuardrailsConfigModel
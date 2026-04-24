"""Merchant bot detection helpers."""

from httpx import Request

_KNOWN_BOT_UA_SUBSTRINGS = (
    "chatgpt-user",
    "perplexitybot",
    "gptbot",
    "anthropic-ai",
    "ccbot",
    "claude-web",
    "claudebot",
    "cohere-ai",
    "youbot",
    "diffbot",
    "oai-searchbot",
    "meta-externalagent",
    "timpibot",
    "amazonbot",
    "bytespider",
    "perplexity-user",
    "googlebot",
    "bot",
    "curl",
    "wget",
)


def default_bot_detector(request: Request) -> bool:
    user_agent = request.headers.get("user-agent", "")
    accept = request.headers.get("accept", "")
    sec_ch_ua = request.headers.get("sec-ch-ua")
    accept_language = request.headers.get("accept-language")

    lower_case_user_agent = user_agent.lower()
    bot_ua_match = any(bot in lower_case_user_agent for bot in _KNOWN_BOT_UA_SUBSTRINGS)

    headless_indicators = "headless" in lower_case_user_agent or "puppeteer" in lower_case_user_agent or not sec_ch_ua
    is_browser_missing_sec_ch_ua = (
        "headless" not in lower_case_user_agent and "puppeteer" not in lower_case_user_agent and not sec_ch_ua
    )
    missing_headers = not accept or not accept_language

    if "safari" in lower_case_user_agent or "mozilla" in lower_case_user_agent:
        if headless_indicators and is_browser_missing_sec_ch_ua:
            return False

    return bot_ua_match or headless_indicators or missing_headers

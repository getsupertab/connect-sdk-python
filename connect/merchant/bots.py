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

_CHROMIUM_UA_SUBSTRINGS = (
    "chrome/",
    "chromium/",
    "edg/",
    "edga/",
    "opr/",
    "opera/",
    "samsungbrowser/",
)
_IOS_WEBKIT_BROWSER_UA_SUBSTRINGS = ("crios/", "edgios/", "fxios/")


def _user_agent_can_omit_sec_ch_ua(lower_case_user_agent: str) -> bool:
    """Return whether this UA is allowed to omit the Sec-CH-UA header.

    Chromium-family browsers generally send Sec-CH-UA, but most browser
    user-agent strings still include Mozilla and Safari compatibility tokens.
    Keep this exception limited to browsers/platforms that do not reliably
    support UA Client Hints: Safari, Firefox, and iOS WebKit browser wrappers.
    """
    is_firefox = "firefox/" in lower_case_user_agent or "fxios/" in lower_case_user_agent
    is_ios_webkit_browser = any(browser in lower_case_user_agent for browser in _IOS_WEBKIT_BROWSER_UA_SUBSTRINGS)
    is_safari = (
        "safari/" in lower_case_user_agent
        and "applewebkit/" in lower_case_user_agent
        and not any(browser in lower_case_user_agent for browser in _CHROMIUM_UA_SUBSTRINGS)
    )

    return is_firefox or is_ios_webkit_browser or is_safari


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

    if _user_agent_can_omit_sec_ch_ua(lower_case_user_agent):
        if headless_indicators and is_browser_missing_sec_ch_ua:
            return False

    return bot_ua_match or headless_indicators or missing_headers

import os
import json


def call_llm(system_prompt: str, user_prompt: str) -> dict:
    provider = os.getenv("LLM_PROVIDER", "gemini").lower()

    try:
        if provider == "gemini":
            return _call_gemini(system_prompt, user_prompt)

        elif provider == "openai":
            return _call_openai(system_prompt, user_prompt)

        else:
            raise ValueError(
                f"Unknown LLM_PROVIDER: {provider}. Use 'gemini' or 'openai'."
            )

    except Exception as e:
        if e.__class__.__name__ == "ResourceExhausted":
            return {
                "status": "error",
                "message": "Gemini API quota exceeded. Please wait and try again later."
            }
        raise


def _call_gemini(system_prompt: str, user_prompt: str) -> dict:
    import google.generativeai as genai

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not set in environment")

    genai.configure(api_key=api_key)

    model = genai.GenerativeModel(
        model_name=os.getenv("LLM_MODEL", "gemini-2.5-flash"),
        system_instruction=system_prompt,
    )

    response = model.generate_content(user_prompt)
    raw_text = response.text.strip()

    return _parse_llm_response(raw_text)


def _call_openai(system_prompt: str, user_prompt: str) -> dict:
    from openai import OpenAI

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not set in environment")

    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
    )

    raw_text = response.choices[0].message.content.strip()
    return _parse_llm_response(raw_text)


def _parse_llm_response(raw_text: str) -> dict:
    if raw_text.startswith("```"):
        lines = raw_text.split("\n")
        lines = [line for line in lines if not line.startswith("```")]
        raw_text = "\n".join(lines)

    try:
        return json.loads(raw_text.strip())
    except json.JSONDecodeError as e:
        return {
            "verdict": "UNKNOWN",
            "confidence": "LOW",
            "risk_score": -1,
            "threat_category": "Parse Error",
            "reasons": [f"LLM response parse nahi hua: {str(e)}"],
            "behavior_summary": raw_text[:500],
            "recommended_action": "INVESTIGATE",
            "ioc_highlights": [],
        }